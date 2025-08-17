// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{self, Commands, Object, Policy},
    from_json_str, get_pcr_count, parse_pcr_selection, AuthSession, Command, CommandIo, Envelope,
    SessionData, TpmDevice, TpmError,
};
use json;
use lexopt::prelude::*;
use pest::iterators::{Pair, Pairs};
use pest::Parser;
use pest_derive::Parser;
use serde_json;
use std::io::{self, Write};
use tpm2_protocol::{
    data::{Tpm2b, Tpm2bDigest, TpmAlgId, TpmRh, TpmlDigest, TpmtSymDefObject},
    message::{
        TpmFlushContextCommand, TpmPolicyGetDigestCommand, TpmPolicyOrCommand, TpmPolicyPcrCommand,
        TpmPolicySecretCommand, TpmStartAuthSessionCommand,
    },
    TpmSession,
};

#[derive(Parser)]
#[grammar = "command/policy.pest"]
pub struct PolicyParser;

#[derive(Debug, PartialEq, Clone)]
enum PolicyAst {
    Pcr {
        selection: String,
        digest: Option<String>,
        count: Option<u32>,
    },
    Secret {
        auth_handle: String,
    },
    Or(Vec<PolicyAst>),
}

const ABOUT: &str = "Builds a policy using a policy expression";
const USAGE: &str = "tpm2sh policy [OPTIONS] <EXPRESSION>";
const ARGS: &[CommandLineArgument] = &[("<EXPRESSION>", "e.g. 'pcr(\"sha256:0\",\\\"...\\\")'")];
const OPTIONS: &[CommandLineOption] = &[
    (None, "--auth", "<AUTH>", "Authorization value"),
    (
        Some("-p"),
        "--partial",
        "",
        "Enable partial consumption of the PCR object",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

fn parse_quoted_string(pair: Pair<'_, Rule>) -> Result<String, TpmError> {
    if pair.as_rule() != Rule::quoted_string {
        return Err(TpmError::Parse("expected a quoted string".to_string()));
    }
    let inner_str = pair.into_inner().next().unwrap().as_str();
    Ok(inner_str.to_string())
}

fn parse_policy_internal(mut pairs: Pairs<'_, Rule>) -> Result<PolicyAst, TpmError> {
    let pair = pairs
        .next()
        .ok_or_else(|| TpmError::Parse("expected a policy expression".to_string()))?;

    let ast = match pair.as_rule() {
        Rule::pcr_expression => {
            let mut inner_pairs = pair.into_inner();
            let selection = parse_quoted_string(inner_pairs.next().unwrap())?;
            let digest = inner_pairs.next().map(parse_quoted_string).transpose()?;
            let count = inner_pairs
                .next()
                .map(|p| p.as_str().parse::<u32>())
                .transpose()
                .map_err(|e| TpmError::Parse(e.to_string()))?;

            PolicyAst::Pcr {
                selection,
                digest,
                count,
            }
        }
        Rule::secret_expression => {
            let auth_handle = parse_quoted_string(pair.into_inner().next().unwrap())?;
            PolicyAst::Secret { auth_handle }
        }
        Rule::or_expression => {
            let mut or_pairs = pair.into_inner();
            let policy_list_pairs = or_pairs.next().unwrap().into_inner();
            let branches = policy_list_pairs
                .map(|p| parse_policy_internal(p.into_inner()))
                .collect::<Result<_, _>>()?;
            PolicyAst::Or(branches)
        }
        _ => {
            return Err(TpmError::Parse(format!(
                "unexpected policy expression part: {:?}",
                pair.as_rule()
            )))
        }
    };

    if pairs.next().is_some() {
        return Err(TpmError::Parse("unexpected trailing input".to_string()));
    }

    Ok(ast)
}

fn parse_policy_expression(input: &str) -> Result<PolicyAst, TpmError> {
    let pairs = PolicyParser::parse(Rule::policy_expression, input)
        .map_err(|e| TpmError::Parse(e.to_string()))?;
    let mut root_pairs = pairs.clone();
    parse_policy_internal(root_pairs.next().unwrap().into_inner())
}

struct PolicyExecutor<'a, 'b, W: Write> {
    chip: &'a mut TpmDevice,
    io: &'b mut CommandIo<W>,
    auth: &'b cli::AuthArgs,
    pcr_count: usize,
    partial: bool,
    log_format: cli::LogFormat,
}

impl<W: Write> PolicyExecutor<'_, '_, W> {
    fn execute_pcr_policy(
        &mut self,
        session_handle: TpmSession,
        selection: &str,
        digest: Option<&String>,
        count: Option<&u32>,
    ) -> Result<(), TpmError> {
        let pcr_output_obj = self.io.consume_object(|obj| {
            if let Object::Pcrs(p) = obj {
                if let Some(c) = count {
                    return p.update_counter == *c;
                }
                true
            } else {
                false
            }
        })?;

        let pcr_digest_bytes = if let Some(digest) = digest {
            hex::decode(digest).map_err(|e| TpmError::Parse(e.to_string()))?
        } else {
            let Object::Pcrs(pcr_output) = pcr_output_obj else {
                unreachable!();
            };

            let (bank_name, pcr_index_str) = selection.split_once(':').ok_or_else(|| {
                TpmError::Parse(
                    "pcr selection must be in 'alg:pcr' format when sourcing digest from pipeline"
                        .to_string(),
                )
            })?;

            let bank = pcr_output.banks.get(bank_name).ok_or_else(|| {
                TpmError::Execution(format!(
                    "pcr bank '{bank_name}' not found in pipeline object"
                ))
            })?;

            let digest_hex = bank.get(pcr_index_str).ok_or_else(|| {
                TpmError::Execution(format!(
                    "pcr index '{pcr_index_str}' not found in bank '{bank_name}' in pipeline object"
                ))
            })?;

            if self.partial {
                let mut pcr_output_modified = pcr_output.clone();
                if let Some(b) = pcr_output_modified.banks.get_mut(bank_name) {
                    b.remove(pcr_index_str);
                }

                if !pcr_output_modified.is_empty() {
                    self.io.push_object(Object::Pcrs(pcr_output_modified));
                }
            }

            hex::decode(digest_hex).map_err(|e| TpmError::Parse(e.to_string()))?
        };

        let pcr_selection = parse_pcr_selection(selection, self.pcr_count)?;
        let pcr_digest = Tpm2bDigest::try_from(pcr_digest_bytes.as_slice())?;

        let cmd = TpmPolicyPcrCommand {
            pcr_digest,
            pcrs: pcr_selection,
        };
        let handles = [session_handle.into()];
        let sessions = crate::get_auth_sessions(&cmd, &handles, self.io.session.as_ref(), None)?;
        self.chip
            .execute(&cmd, Some(&handles), &sessions, self.log_format)?;

        Ok(())
    }

    fn execute_secret_policy(
        &mut self,
        session_handle: TpmSession,
        auth_handle_str: &str,
    ) -> Result<(), TpmError> {
        let auth_handle = crate::parse_hex_u32(auth_handle_str)?;
        let cmd = TpmPolicySecretCommand {
            nonce_tpm: Tpm2b::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2b::default(),
            expiration: 0,
        };
        let handles = [auth_handle, session_handle.into()];
        let sessions = crate::get_auth_sessions(
            &cmd,
            &handles,
            self.io.session.as_ref(),
            self.auth.auth.as_deref(),
        )?;
        self.chip
            .execute(&cmd, Some(&handles), &sessions, self.log_format)?;
        Ok(())
    }

    fn execute_or_policy(
        &mut self,
        session_handle: TpmSession,
        branches: &[PolicyAst],
    ) -> Result<(), TpmError> {
        let mut branch_digests = TpmlDigest::new();
        for branch_ast in branches {
            let branch_handle = start_trial_session(
                self.chip,
                self.io.session.as_ref(),
                cli::SessionType::Trial,
                self.log_format,
            )?;

            self.execute_policy_ast(branch_handle, branch_ast)?;

            let digest = get_policy_digest(
                self.chip,
                self.io.session.as_ref(),
                branch_handle,
                self.log_format,
            )?;
            branch_digests.try_push(digest)?;

            flush_session(self.chip, branch_handle, self.log_format)?;
        }

        let cmd = TpmPolicyOrCommand {
            p_hash_list: branch_digests,
        };
        let handles = [session_handle.into()];
        let sessions = crate::get_auth_sessions(&cmd, &handles, self.io.session.as_ref(), None)?;
        self.chip
            .execute(&cmd, Some(&handles), &sessions, self.log_format)?;

        Ok(())
    }

    fn execute_policy_ast(
        &mut self,
        session_handle: TpmSession,
        ast: &PolicyAst,
    ) -> Result<(), TpmError> {
        match ast {
            PolicyAst::Pcr {
                selection,
                digest,
                count,
            } => {
                self.execute_pcr_policy(session_handle, selection, digest.as_ref(), count.as_ref())
            }
            PolicyAst::Secret { auth_handle } => {
                self.execute_secret_policy(session_handle, auth_handle)
            }
            PolicyAst::Or(branches) => self.execute_or_policy(session_handle, branches),
        }
    }
}

fn start_trial_session(
    chip: &mut TpmDevice,
    session: Option<&AuthSession>,
    session_type: cli::SessionType,
    log_format: cli::LogFormat,
) -> Result<TpmSession, TpmError> {
    let auth_hash = session.map_or(TpmAlgId::Sha256, |s| s.auth_hash);

    let cmd = TpmStartAuthSessionCommand {
        nonce_caller: Tpm2b::default(),
        encrypted_salt: Tpm2b::default(),
        session_type: session_type.into(),
        symmetric: TpmtSymDefObject::default(),
        auth_hash,
    };
    let (resp, _) = chip.execute(
        &cmd,
        Some(&[TpmRh::Null as u32, TpmRh::Null as u32]),
        &[],
        log_format,
    )?;
    let start_resp = resp
        .StartAuthSession()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    Ok(start_resp.session_handle)
}

fn flush_session(
    chip: &mut TpmDevice,
    handle: TpmSession,
    log_format: cli::LogFormat,
) -> Result<(), TpmError> {
    let cmd = TpmFlushContextCommand {
        flush_handle: handle.into(),
    };
    chip.execute(&cmd, Some(&[]), &[], log_format)?;
    Ok(())
}

fn get_policy_digest(
    chip: &mut TpmDevice,
    session: Option<&AuthSession>,
    session_handle: TpmSession,
    log_format: cli::LogFormat,
) -> Result<Tpm2bDigest, TpmError> {
    let cmd = TpmPolicyGetDigestCommand {};
    let handles = [session_handle.into()];
    let sessions = crate::get_auth_sessions(&cmd, &handles, session, None)?;
    let (resp, _) = chip.execute(&cmd, Some(&handles), &sessions, log_format)?;
    let digest_resp = resp
        .PolicyGetDigest()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    Ok(digest_resp.policy_digest)
}

impl Command for Policy {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("policy", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Policy::default();
        let mut expression_arg = None;

        while let Some(arg) = parser.next()? {
            match arg {
                Long("auth") => args.auth.auth = Some(parser.value()?.string()?),
                Short('p') | Long("partial") => args.partial = true,
                Short('h') | Long("help") => {
                    Self::help();
                    std::process::exit(0);
                }
                Value(val) if expression_arg.is_none() => {
                    expression_arg = Some(val);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }
        args.expression = expression_arg
            .ok_or_else(|| {
                TpmError::Execution("missing required positional argument <EXPRESSION>".to_string())
            })?
            .string()?;
        Ok(Commands::Policy(args))
    }

    /// Run 'policy'.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on failure.
    fn run(&self, chip: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError> {
        let mut io = CommandIo::new(io::stdin(), io::stdout(), log_format)?;

        let session_obj = io.consume_object(|obj| {
            if let Object::Context(val) = obj {
                if let Ok(env) = serde_json::from_value::<Envelope>(val.clone()) {
                    return env.object_type == "session";
                }
            }
            false
        })?;

        let Object::Context(envelope_value) = session_obj else {
            unreachable!();
        };

        let json_value = from_json_str(&envelope_value.to_string(), "session")?;
        let data_str = json::stringify(json_value);
        let mut session_data: SessionData = serde_json::from_str(&data_str)?;

        let ast = parse_policy_expression(&self.expression)
            .map_err(|e| TpmError::Parse(format!("failed to parse policy expression: {e}")))?;

        let pcr_count = get_pcr_count(chip, log_format)?;
        let session_handle = TpmSession(session_data.handle);

        let mut executor = PolicyExecutor {
            chip,
            io: &mut io,
            auth: &self.auth,
            pcr_count,
            partial: self.partial,
            log_format,
        };
        executor.execute_policy_ast(session_handle, &ast)?;

        let final_digest =
            get_policy_digest(chip, io.session.as_ref(), session_handle, log_format)?;
        session_data.policy_digest = hex::encode(&*final_digest);

        let next_session = Object::Context(serde_json::to_value(Envelope {
            version: 1,
            object_type: "session".to_string(),
            data: serde_json::to_value(session_data)?,
        })?);

        io.push_object(next_session);
        io.finalize()
    }
}
