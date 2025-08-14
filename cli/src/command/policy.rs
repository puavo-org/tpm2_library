// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{self, Object, Policy, SessionType},
    from_json_str, get_pcr_count, parse_pcr_selection,
    policy::{parse_policy_expression, Policy as PolicyAst},
    AuthSession, Command, CommandIo, Envelope, SessionData, TpmDevice, TpmError,
};
use std::io;
use tpm2_protocol::{
    data::{Tpm2b, Tpm2bDigest, TpmAlgId, TpmRh, TpmlDigest, TpmtSymDefObject},
    message::{
        TpmFlushContextCommand, TpmPolicyGetDigestCommand, TpmPolicyOrCommand, TpmPolicyPcrCommand,
        TpmPolicySecretCommand, TpmStartAuthSessionCommand,
    },
    TpmSession,
};

fn execute_policy_ast(
    chip: &mut TpmDevice,
    cmd_auth: &cli::AuthArgs,
    session: Option<&AuthSession>,
    policy_session_handle: TpmSession,
    ast: &PolicyAst,
    pcr_count: usize,
) -> Result<(), TpmError> {
    match ast {
        PolicyAst::Pcr {
            selection_str,
            digest_str,
        } => {
            let pcr_selection = parse_pcr_selection(selection_str, pcr_count)?;
            let pcr_digest_bytes =
                hex::decode(digest_str).map_err(|e| TpmError::Parse(e.to_string()))?;
            let pcr_digest = Tpm2bDigest::try_from(pcr_digest_bytes.as_slice())?;

            let cmd = TpmPolicyPcrCommand {
                pcr_digest,
                pcrs: pcr_selection,
            };
            let handles = [policy_session_handle.into()];
            let sessions = crate::get_auth_sessions(&cmd, &handles, session, None)?;
            chip.execute(&cmd, Some(&handles), &sessions)?;
        }
        PolicyAst::Secret { auth_handle_str } => {
            let auth_handle = crate::parse_hex_u32(auth_handle_str)?;
            let cmd = TpmPolicySecretCommand {
                nonce_tpm: Tpm2b::default(),
                cp_hash_a: Tpm2bDigest::default(),
                policy_ref: Tpm2b::default(),
                expiration: 0,
            };
            let handles = [auth_handle, policy_session_handle.into()];
            let sessions =
                crate::get_auth_sessions(&cmd, &handles, session, cmd_auth.auth.as_deref())?;
            chip.execute(&cmd, Some(&handles), &sessions)?;
        }
        PolicyAst::Or(branches) => {
            let mut branch_digests = TpmlDigest::new();
            for branch_ast in branches {
                let branch_handle = start_trial_session(chip, session, SessionType::Trial)?;

                execute_policy_ast(
                    chip,
                    cmd_auth,
                    session,
                    branch_handle,
                    branch_ast,
                    pcr_count,
                )?;

                let digest = get_policy_digest(chip, session, branch_handle)?;
                branch_digests.try_push(digest)?;

                flush_session(chip, branch_handle)?;
            }

            let cmd = TpmPolicyOrCommand {
                p_hash_list: branch_digests,
            };
            let handles = [policy_session_handle.into()];
            let sessions = crate::get_auth_sessions(&cmd, &handles, session, None)?;
            chip.execute(&cmd, Some(&handles), &sessions)?;
        }
    }
    Ok(())
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
        let mut io = CommandIo::new(io::stdin(), io::stdout(), session);

        let session_obj = io.next_object()?;
        let mut session_data: SessionData = match session_obj {
            Object::Context(v) => from_json_str(&v.to_string(), "session")?,
            _ => {
                return Err(TpmError::Execution(
                    "input pipeline must contain a session object".to_string(),
                ))
            }
        };

        let ast = parse_policy_expression(&self.expression)
            .map_err(|e| TpmError::Parse(format!("failed to parse policy expression: {e}")))?;

        let pcr_count = get_pcr_count(chip)?;
        let policy_session_handle = TpmSession(session_data.handle);

        execute_policy_ast(
            chip,
            &self.auth,
            session,
            policy_session_handle,
            &ast,
            pcr_count,
        )?;

        let final_digest = get_policy_digest(chip, session, policy_session_handle)?;
        session_data.policy_digest = hex::encode(&*final_digest);

        let new_session_obj = Object::Context(serde_json::to_value(Envelope {
            version: 1,
            object_type: "session".to_string(),
            data: serde_json::to_value(session_data)?,
        })?);

        io.push_object(new_session_obj);
        io.finalize()
    }
}
