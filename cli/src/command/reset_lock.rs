// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::ResetLock, get_auth_sessions, AuthSession, Command, TpmDevice, TpmError};
use tpm2_protocol::{data::TpmRh, message::TpmDictionaryAttackLockResetCommand};

impl Command for ResetLock {
    /// Runs `reset-lock`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, session: Option<&AuthSession>) -> Result<(), TpmError> {
        let command = TpmDictionaryAttackLockResetCommand {};
        let handles = [TpmRh::Lockout as u32];

        let sessions = get_auth_sessions(&command, &handles, session, self.auth.auth.as_deref())?;

        let (resp, _) = chip.execute(&command, Some(&handles), &sessions)?;
        resp.DictionaryAttackLockReset()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        Ok(())
    }
}
