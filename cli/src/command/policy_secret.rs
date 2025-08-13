// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::PolicySecret, get_auth_sessions, resolve_object_handle, AuthSession, Command, CommandIo,
    TpmDevice, TpmError,
};
use std::io;
use tpm2_protocol::{
    data::{Tpm2b, Tpm2bDigest},
    message::TpmPolicySecretCommand,
};

impl Command for PolicySecret {
    /// Executes the `policy secret` command (not in training mode).
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on failure.
    fn run(&self, chip: &mut TpmDevice, session: Option<&AuthSession>) -> Result<(), TpmError> {
        let mut io = CommandIo::new(io::stdin(), io::stdout(), session);
        let auth_object = io.next_object()?;
        let policy_session_object = io.next_object()?;

        let auth_handle = resolve_object_handle(chip, &auth_object)?;
        let policy_session_handle = resolve_object_handle(chip, &policy_session_object)?;

        let handles = [auth_handle.into(), policy_session_handle.into()];
        let cmd = TpmPolicySecretCommand {
            nonce_tpm: Tpm2b::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2b::default(),
            expiration: self.expiration,
        };

        let sessions = get_auth_sessions(&cmd, &handles, session, self.auth.auth.as_deref())?;

        let (resp, _) = chip.execute(&cmd, Some(&handles), &sessions)?;
        resp.PolicySecret()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        io.push_object(policy_session_object);
        io.finalize()
    }
}
