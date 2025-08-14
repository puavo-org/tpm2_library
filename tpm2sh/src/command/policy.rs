// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{self, Object, Policy, SessionType},
    from_json_str, get_pcr_count, parse_pcr_selection, AuthSession, Command, CommandIo, Envelope,
    SessionData, TpmDevice, TpmError,
};
use pest::iterators::{Pair, Pairs};
use pest::Parser;
use pest_derive::Parser;
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
struct PolicyParser;

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

struct PolicyExecutor<'a, 'b, 'c, W: Write> {
    chip: &'a mut TpmDevice,
    io: &'b mut CommandIo<'c, W>,
    auth: &'c cli::AuthArgs,
    session: Option<&'c AuthSession>,
    session_handle: TpmSession,
    pcr_count: usize,
    partial: bool,
}

impl<W: Write> PolicyExecutor<'_, '_, '_, W> {
    fn execute_pcr_policy(
        &mut self,
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
        let handles = [self.session_handle.into()];
        let sessions = crate::get_auth_sessions(&cmd, &handles, self.session, None)?;
        self.chip.execute(&cmd, Some(&handles), &sessions)?;

        Ok(())
    }

    fn execute_secret_policy(&mut self, auth_handle: &str) -> Result<(), TpmError> {
        let auth_handle = crate::parse_hex_u32(auth_handle)?;
        let cmd = TpmPolicySecretCommand {
            nonce_tpm: Tpm2b::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2b::default(),
            expiration: 0,
        };
        let handles = [auth_handle, self.session_handle.into()];
        let sessions =
            crate::get_auth_sessions(&cmd, &handles, self.session, self.auth.auth.as_deref())?;
        self.chip.execute(&cmd, Some(&handles), &sessions)?;
        Ok(())
    }

    fn execute_or_policy(&mut self, branches: &[PolicyAst]) -> Result<(), TpmError> {
        let mut branch_digests = TpmlDigest::new();
        for branch_ast in branches {
            let branch_handle = start_trial_session(self.chip, self.session, SessionType::Trial)?;

            self.execute_policy_ast(branch_ast)?;

            let digest = get_policy_digest(self.chip, self.session, branch_handle)?;
            branch_digests.try_push(digest)?;

            flush_session(self.chip, branch_handle)?;
        }

        let cmd = TpmPolicyOrCommand {
            p_hash_list: branch_digests,
        };
        let handles = [self.session_handle.into()];
        let sessions = crate::get_auth_sessions(&cmd, &handles, self.session, None)?;
        self.chip.execute(&cmd, Some(&handles), &sessions)?;

        Ok(())
    }

    fn execute_policy_ast(&mut self, ast: &PolicyAst) -> Result<(), TpmError> {
        match ast {
            PolicyAst::Pcr {
                selection,
                digest,
                count,
            } => self.execute_pcr_policy(selection, digest.as_ref(), count.as_ref()),
            PolicyAst::Secret { auth_handle } => self.execute_secret_policy(auth_handle),
            PolicyAst::Or(branches) => self.execute_or_policy(branches),
        }
    }
}

fn start_trial_session(
    chip: &mut TpmDevice,
    session: Option<&AuthSession>,
    session_type: SessionType,
) -> Result<TpmSession, TpmError> {
    let auth_hash = session.map_or(TpmAlgId::Sha256, |s| s.auth_hash);

    let cmd = TpmStartAuthSessionCommand {
        nonce_caller: Tpm2b::default(),
        encrypted_salt: Tpm2b::default(),
        session_type: session_type.into(),
        symmetric: TpmtSymDefObject::default(),
        auth_hash,
    };
    let (resp, _) = chip.execute(&cmd, Some(&[TpmRh::Null as u32, TpmRh::Null as u32]), &[])?;
    let start_resp = resp
        .StartAuthSession()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    Ok(start_resp.session_handle)
}

fn flush_session(chip: &mut TpmDevice, handle: TpmSession) -> Result<(), TpmError> {
    let cmd = TpmFlushContextCommand {
        flush_handle: handle.into(),
    };
    chip.execute(&cmd, Some(&[]), &[])?;
    Ok(())
}

fn get_policy_digest(
    chip: &mut TpmDevice,
    session: Option<&AuthSession>,
    session_handle: TpmSession,
) -> Result<Tpm2bDigest, TpmError> {
    let cmd = TpmPolicyGetDigestCommand {};
    let handles = [session_handle.into()];
    let sessions = crate::get_auth_sessions(&cmd, &handles, session, None)?;
    let (resp, _) = chip.execute(&cmd, Some(&handles), &sessions)?;
    let digest_resp = resp
        .PolicyGetDigest()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    Ok(digest_resp.policy_digest)
}

impl Command for Policy {
    /// Run 'policy'.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on failure.
    fn run(&self, chip: &mut TpmDevice, session: Option<&AuthSession>) -> Result<(), TpmError> {
        let mut io = CommandIo::new(io::stdin(), io::stdout(), session)?;

        let session_obj = io.consume_object(|obj| {
            if let Object::Context(v) = obj {
                if let Ok(env) = serde_json::from_value::<Envelope>(v.clone()) {
                    return env.object_type == "session";
                }
            }
            false
        })?;

        let Object::Context(envelope_value) = session_obj else {
            unreachable!();
        };

        let mut session_data: SessionData = from_json_str(&envelope_value.to_string(), "session")?;

        let ast = parse_policy_expression(&self.expression)
            .map_err(|e| TpmError::Parse(format!("failed to parse policy expression: {e}")))?;

        let pcr_count = get_pcr_count(chip)?;
        let session_handle = TpmSession(session_data.handle);

        let mut executor = PolicyExecutor {
            chip,
            io: &mut io,
            auth: &self.auth,
            session,
            session_handle,
            pcr_count,
            partial: self.partial,
        };
        executor.execute_policy_ast(&ast)?;

        let final_digest = get_policy_digest(chip, session, session_handle)?;
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
