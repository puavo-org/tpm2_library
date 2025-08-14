// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{self, Object, Policy, SessionType},
    from_json_str, get_pcr_count, parse_pcr_selection, AuthSession, Command, CommandIo, Envelope,
    SessionData, TpmDevice, TpmError,
};
use pest::iterators::Pairs;
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

/// An Abstract Syntax Tree (AST) for a policy expression.
#[derive(Debug, PartialEq)]
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

/// A helper function to parse an inner quoted string.
fn parse_quoted_string(pairs: Pairs<Rule>) -> Result<String, TpmError> {
    let mut pairs = pairs.into_iter();
    let inner_pair = pairs
        .next()
        .ok_or_else(|| TpmError::Parse("expected a quoted string".to_string()))?;
    if inner_pair.as_rule() != Rule::quoted_string {
        return Err(TpmError::Parse("expected a quoted string".to_string()));
    }
    let inner_str = inner_pair
        .into_inner()
        .next()
        .ok_or_else(|| TpmError::Parse("expected content for the quoted string".to_string()))?;
    Ok(inner_str.as_str().to_string())
}

/// A helper function to parse a list of policy expressions.
fn parse_policy_list(pairs: Pairs<Rule>) -> Result<Vec<PolicyAst>, TpmError> {
    pairs
        .into_iter()
        .map(|pair| parse_policy_internal(pair.into_inner()))
        .collect()
}

/// Parses a policy expression from a Pest pair.
fn parse_policy_internal(pairs: Pairs<'_, Rule>) -> Result<PolicyAst, TpmError> {
    let mut pairs = pairs.into_iter();
    let pair = pairs
        .next()
        .ok_or_else(|| TpmError::Parse("expected a policy expression".to_string()))?;

    match pair.as_rule() {
        Rule::pcr_expression => {
            let mut pairs = pair.into_inner();
            let selection = parse_quoted_string(pairs.next().unwrap().into_inner())?;
            let digest = pairs
                .next()
                .map(|p| parse_quoted_string(p.into_inner()))
                .transpose()?;
            let count_str = pairs
                .next()
                .map(|p| p.into_inner().next().unwrap().as_str());

            let count = if let Some(s) = count_str {
                Some(
                    s.parse::<u32>()
                        .map_err(|e| TpmError::Parse(e.to_string()))?,
                )
            } else {
                None
            };

            Ok(PolicyAst::Pcr {
                selection,
                digest,
                count,
            })
        }
        Rule::secret_expression => {
            let auth_handle = parse_quoted_string(pair.into_inner())?;
            Ok(PolicyAst::Secret { auth_handle })
        }
        Rule::or_expression => {
            let list = parse_policy_list(pair.into_inner())?;
            Ok(PolicyAst::Or(list))
        }
        _ => Err(TpmError::Parse(format!(
            "unexpected policy expression part: {:?}",
            pair.as_rule()
        ))),
    }
}

/// Top-level parser function that consumes the entire input.
///
/// # Errors
///
/// Returns a descriptive error if parsing fails.
///
/// # Panics
///
/// Panics if the internal `pest` parser encounters an unexpected unwrap.
fn parse_policy_expression(input: &str) -> Result<PolicyAst, TpmError> {
    let mut pairs = PolicyParser::parse(Rule::policy_expression, input)
        .map_err(|e| TpmError::Parse(e.to_string()))?;

    let policy_ast = parse_policy_internal(pairs.next().unwrap().into_inner())?;

    if pairs.next().is_some() {
        return Err(TpmError::Parse("unexpected trailing input".to_string()));
    }
    Ok(policy_ast)
}

struct PolicyExecutor<'a, 'b, W: Write> {
    chip: &'a mut TpmDevice,
    io: &'b mut CommandIo<'a, W>,
    cmd_auth: &'a cli::AuthArgs,
    session: Option<&'a AuthSession>,
    policy_session_handle: TpmSession,
    pcr_count: usize,
    partial_consumption: bool,
}

impl<W: Write> PolicyExecutor<'_, '_, W> {
    fn execute_policy_ast(&mut self, ast: &PolicyAst) -> Result<(), TpmError> {
        match ast {
            PolicyAst::Pcr {
                selection,
                digest,
                count,
            } => {
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
                        TpmError::Parse(format!(
                            "pcr selection '{selection}' must be in 'alg:pcr' format when sourcing digest from pipeline"
                        ))
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

                    if self.partial_consumption {
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
                let handles = [self.policy_session_handle.into()];
                let sessions = crate::get_auth_sessions(&cmd, &handles, self.session, None)?;
                self.chip.execute(&cmd, Some(&handles), &sessions)?;
            }
            PolicyAst::Secret { auth_handle } => {
                let auth_handle = crate::parse_hex_u32(auth_handle)?;
                let cmd = TpmPolicySecretCommand {
                    nonce_tpm: Tpm2b::default(),
                    cp_hash_a: Tpm2bDigest::default(),
                    policy_ref: Tpm2b::default(),
                    expiration: 0,
                };
                let handles = [auth_handle, self.policy_session_handle.into()];
                let sessions = crate::get_auth_sessions(
                    &cmd,
                    &handles,
                    self.session,
                    self.cmd_auth.auth.as_deref(),
                )?;
                self.chip.execute(&cmd, Some(&handles), &sessions)?;
            }
            PolicyAst::Or(branches) => {
                let mut branch_digests = TpmlDigest::new();
                for branch_ast in branches {
                    let branch_handle =
                        start_trial_session(self.chip, self.session, SessionType::Trial)?;

                    self.execute_policy_ast(branch_ast)?;

                    let digest = get_policy_digest(self.chip, self.session, branch_handle)?;
                    branch_digests.try_push(digest)?;

                    flush_session(self.chip, branch_handle)?;
                }

                let cmd = TpmPolicyOrCommand {
                    p_hash_list: branch_digests,
                };
                let handles = [self.policy_session_handle.into()];
                let sessions = crate::get_auth_sessions(&cmd, &handles, self.session, None)?;
                self.chip.execute(&cmd, Some(&handles), &sessions)?;
            }
        }
        Ok(())
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
    policy_session_handle: TpmSession,
) -> Result<Tpm2bDigest, TpmError> {
    let cmd = TpmPolicyGetDigestCommand {};
    let handles = [policy_session_handle.into()];
    let sessions = crate::get_auth_sessions(&cmd, &handles, session, None)?;
    let (resp, _) = chip.execute(&cmd, Some(&handles), &sessions)?;
    let digest_resp = resp
        .PolicyGetDigest()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    Ok(digest_resp.policy_digest)
}

impl Command for Policy {
    /// Executes the `policy` command.
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
        let policy_session_handle = TpmSession(session_data.handle);

        {
            let mut executor = PolicyExecutor {
                chip,
                io: &mut io,
                cmd_auth: &self.auth,
                session,
                policy_session_handle,
                pcr_count,
                partial_consumption: self.partial,
            };

            executor.execute_policy_ast(&ast)?;

            let final_digest =
                get_policy_digest(executor.chip, executor.session, policy_session_handle)?;
            session_data.policy_digest = hex::encode(&*final_digest);
        }

        let new_session_obj = Object::Context(serde_json::to_value(Envelope {
            version: 1,
            object_type: "session".to_string(),
            data: serde_json::to_value(session_data)?,
        })?);

        io.push_object(new_session_obj);
        io.finalize()
    }
}
