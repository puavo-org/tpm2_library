// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{create_auth, util, TpmError};
use rand::RngCore;
use tpm2_protocol::{
    data::{self, Tpm2bAuth, TpmRh},
    message::TpmHeader,
};
use tracing::debug;

/// Manages the state of an active authorization session.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub handle: tpm2_protocol::TpmSession,
    pub nonce_tpm: data::Tpm2bNonce,
    pub attributes: data::TpmaSession,
    pub hmac_key: data::Tpm2bAuth,
    pub auth_hash: data::TpmAlgId,
}

/// Builds the authorization area for a password-based session.
///
/// # Errors
///
/// Returns `TpmError` on failure.
pub fn build_password_session(auth: Option<&str>) -> Result<Vec<data::TpmsAuthCommand>, TpmError> {
    match auth {
        Some(password) => {
            debug!(auth_len = password.len(), "building password session");
            Ok(vec![data::TpmsAuthCommand {
                session_handle: tpm2_protocol::TpmSession(TpmRh::Password as u32),
                nonce: data::Tpm2bNonce::default(),
                session_attributes: data::TpmaSession::empty(),
                hmac: Tpm2bAuth::try_from(password.as_bytes())?,
            }])
        }
        None => Ok(Vec::new()),
    }
}

/// Prepares the authorization sessions for a command, handling either a full
/// `AuthSession` context or a simple password.
///
/// # Errors
///
/// Returns a `TpmError` if building the command parameters or creating the
/// authorization HMAC fails.
pub fn get_auth_sessions<C>(
    command: &C,
    handles: &[u32],
    session: Option<&AuthSession>,
    password: Option<&str>,
) -> Result<Vec<data::TpmsAuthCommand>, TpmError>
where
    C: TpmHeader,
{
    if let Some(session) = session {
        let params = util::build_to_vec(command)?;

        let nonce_size = tpm2_protocol::tpm_hash_size(&session.auth_hash).ok_or_else(|| {
            TpmError::Execution(format!(
                "session has an invalid hash algorithm: {}",
                session.auth_hash
            ))
        })?;

        let mut nonce_bytes = vec![0; nonce_size];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce_caller = data::Tpm2bNonce::try_from(nonce_bytes.as_slice())?;

        let auth = create_auth(session, &nonce_caller, C::COMMAND, handles, &params)?;
        Ok(vec![auth])
    } else {
        let effective_password = if C::WITH_SESSIONS && password.is_none() {
            Some("")
        } else {
            password
        };
        build_password_session(effective_password)
    }
}
