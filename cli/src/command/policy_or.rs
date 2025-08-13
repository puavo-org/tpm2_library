// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Object, PolicyOrArgs},
    read_session_data_from_file, AuthSession, CommandIo, SessionData, TpmError,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::io;
use tpm2_protocol::data::TpmAlgId;

/// Executes the `policy-or` command in training mode.
///
/// # Errors
///
/// Returns a `TpmError` on failure.
pub fn run(args: &PolicyOrArgs, session: Option<&AuthSession>) -> Result<(), TpmError> {
    let mut io = CommandIo::new(io::stdin(), io::stdout(), session);
    let session_obj = io.next_object()?;
    let mut session_data: SessionData = match session_obj {
        Object::Context(s) => serde_json::from_str(&s)?,
        _ => {
            return Err(TpmError::Execution(
                "input pipeline must contain a session object".to_string(),
            ))
        }
    };

    let auth_hash = TpmAlgId::try_from(session_data.auth_hash)
        .map_err(|()| TpmError::Parse("invalid hash algorithm in session".to_string()))?;

    let mut data_to_hash = Vec::new();
    for branch_path in &args.branches {
        let branch_session: SessionData = read_session_data_from_file(branch_path)?;
        let branch_digest = hex::decode(branch_session.policy_digest)
            .map_err(|e| TpmError::Parse(format!("invalid policy digest in branch file: {e}")))?;
        data_to_hash.extend_from_slice(&branch_digest);
    }

    let or_digest = match auth_hash {
        TpmAlgId::Sha256 => Sha256::digest(&data_to_hash).to_vec(),
        TpmAlgId::Sha384 => Sha384::digest(&data_to_hash).to_vec(),
        TpmAlgId::Sha512 => Sha512::digest(&data_to_hash).to_vec(),
        _ => {
            return Err(TpmError::Execution(
                "unsupported hash algorithm".to_string(),
            ))
        }
    };

    session_data.policy_digest = hex::encode(or_digest);
    let new_session_obj = Object::Context(serde_json::to_string(&session_data)?);

    io.push_object(new_session_obj);
    io.finalize()
}
