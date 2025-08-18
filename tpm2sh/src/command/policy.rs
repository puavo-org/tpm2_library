// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{self, Commands, Object, Policy},
    from_json_str, get_pcr_count, parse_pcr_selection, AuthSession, Command, CommandIo, Envelope,
    SessionData, TpmDevice, TpmError,
};
use lexopt::prelude::*;
use pest::iterators::{Pair, Pairs};
use pest::Parser;
use pest_derive::Parser;
use std::io::{self, Write};
use tpm2_protocol::{
    data::{Tpm2b, Tpm2bDigest, TpmAlgId, TpmRh, TpmlDigest, TpmlPcrSelection, TpmtSymDefObject},
    message::{
        TpmFlushContextCommand, TpmPolicyGetDigestCommand, TpmPolicyOrCommand, TpmPolicyPcrCommand,
        TpmPolicySecretCommand, TpmStartAuthSessionCommand,
    },
    TpmParse, TpmSession,
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
const ARGS: &[CommandLineArgument] = &[("EXPRESSION", "e.g. 'pcr(\\\"sha256:0\\\",\\\"...\\\")'")];
const OPTIONS: &[CommandLineOption] = &[
    (None, "--auth", "<AUTH>", "Authorization value"),
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
    log_format: cli::LogFormat,
    session: Option<AuthSession>,
}

impl<W: Write> PolicyExecutor<'_, '_, W> {
    fn execute_pcr_policy(
        &mut self,
        session_handle: TpmSession,
        selection_str: &str,
        digest: Option<&String>,
        _count: Option<&u32>,
    ) -> Result<(), TpmError> {
        let pcr_digest_bytes = hex::decode(digest.ok_or_else(|| {
            TpmError::Execution("PCR digest must be provided as an argument".to_string())
        })?)
        .map_err(|e| TpmError::Parse(e.to_string()))?;

        let pcr_selection = if selection_str.is_empty() {
            let selection_obj = self.io.consume_object(|obj| {
                let cli::Object::TpmObject(s) = obj;
                if let Ok(bytes) = hex::decode(s) {
                    return bytes.len() > 4 && bytes.len() < 100;
                }
                false
            })?;
            let cli::Object::TpmObject(hex_string) = selection_obj;
            let bytes = hex::decode(hex_string)?;
            TpmlPcrSelection::parse(&bytes)?.0
        } else {
            parse_pcr_selection(selection_str, self.pcr_count)?
        };

        let pcr_digest = Tpm2bDigest::try_from(pcr_digest_bytes.as_slice())?;

        let cmd = TpmPolicyPcrCommand {
            pcr_digest,
            pcrs: pcr_selection,
        };
        let handles = [session_handle.into()];
        let sessions = crate::get_auth_sessions(&cmd, &handles, self.session.as_ref(), None)?;
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
            self.session.as_ref(),
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
                self.session.as_ref(),
                cli::SessionType::Trial,
                self.log_format,
            )?;

            self.execute_policy_ast(branch_handle, branch_ast)?;

            let digest = get_policy_digest(
                self.chip,
                self.session.as_ref(),
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
        let sessions = crate::get_auth_sessions(&cmd, &handles, self.session.as_ref(), None)?;
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
        let mut expression_arg: Option<String> = None;

        while let Some(arg) = parser.next()? {
            match arg {
                Long("auth") => args.auth.auth = Some(parser.value()?.string()?),
                Short('h') | Long("help") => {
                    Self::help();
                    std::process::exit(0);
                }
                Value(val) if expression_arg.is_none() => {
                    expression_arg = Some(val.string()?);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }

        if let Some(expression) = expression_arg {
            args.expression = expression;
            Ok(Commands::Policy(args))
        } else {
            Self::help();
            std::process::exit(1);
        }
    }

    /// Run 'policy'.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on failure.
    fn run(&self, chip: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError> {
        let mut io = CommandIo::new(io::stdin(), io::stdout(), log_format)?;
        let session = io.take_session()?;

        let (mut session_data, session_handle, is_trial) = if let Some(s) = session {
            let json_val = from_json_str(&s.original_json, "session")?;
            (SessionData::from_json(&json_val)?, s.handle, false)
        } else {
            let trial_handle =
                start_trial_session(chip, None, cli::SessionType::Trial, log_format)?;
            (
                SessionData {
                    handle: trial_handle.into(),
                    ..Default::default()
                },
                trial_handle,
                true,
            )
        };

        let ast = parse_policy_expression(&self.expression)
            .map_err(|e| TpmError::Parse(format!("failed to parse policy expression: {e}")))?;

        let pcr_count = get_pcr_count(chip, log_format)?;

        let mut executor = PolicyExecutor {
            chip,
            io: &mut io,
            auth: &self.auth,
            pcr_count,
            log_format,
            session: None,
        };
        executor.execute_policy_ast(session_handle, &ast)?;

        let final_digest = get_policy_digest(chip, None, session_handle, log_format)?;
        session_data.policy_digest = hex::encode(&*final_digest);

        if is_trial {
            flush_session(chip, session_handle, log_format)?;
            println!("{}", session_data.policy_digest);
        } else {
            let next_session = Object::TpmObject(
                Envelope {
                    version: 1,
                    object_type: "session".to_string(),
                    data: session_data.to_json(),
                }
                .to_json()
                .dump(),
            );
            io.push_object(next_session);
        }

        io.finalize()
    }
}
