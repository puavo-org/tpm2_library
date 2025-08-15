// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli, cli::Save, get_auth_sessions, AuthSession, Command, TpmDevice, TpmError};
use tpm2_protocol::{data::TpmRh, message::TpmEvictControlCommand};

impl Command for Save {
    /// Runs `save`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(
        &self,
        chip: &mut TpmDevice,
        session: Option<&AuthSession>,
        log_format: cli::LogFormat,
    ) -> Result<(), TpmError> {
        let auth_handle = TpmRh::Owner;
        let handles = [auth_handle as u32, self.object_handle];

        let evict_cmd = TpmEvictControlCommand {
            persistent_handle: self.persistent_handle,
        };

        let sessions = get_auth_sessions(&evict_cmd, &handles, session, self.auth.auth.as_deref())?;

        let (resp, _) = chip.execute(&evict_cmd, Some(&handles), &sessions, log_format)?;
        resp.EvictControl()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        println!("{:#010x}", self.persistent_handle);
        Ok(())
    }
}
