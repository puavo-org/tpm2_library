// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{cli, get_auth_sessions, AuthSession, Command, TpmDevice, TpmError};
use tpm2_protocol::{
    data::TpmRh,
    message::{TpmEvictControlCommand, TpmFlushContextCommand},
    TpmPersistent, TpmTransient,
};

impl Command for cli::Delete {
    /// Runs `delete`.
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
        let handle = self.handle;

        if handle >= TpmRh::PersistentFirst as u32 {
            let persistent_handle = TpmPersistent(handle);
            let auth_handle = TpmRh::Owner;
            let handles = [auth_handle as u32, persistent_handle.into()];
            let evict_cmd = TpmEvictControlCommand { persistent_handle };

            let sessions =
                get_auth_sessions(&evict_cmd, &handles, session, self.auth.auth.as_deref())?;
            let (resp, _) = chip.execute(&evict_cmd, Some(&handles), &sessions, log_format)?;
            resp.EvictControl()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
            println!("{persistent_handle:#010x}");
        } else if handle >= TpmRh::TransientFirst as u32 {
            let flush_handle = TpmTransient(handle);
            let flush_cmd = TpmFlushContextCommand {
                flush_handle: flush_handle.into(),
            };
            let (resp, _) = chip.execute(&flush_cmd, Some(&[]), &[], log_format)?;
            resp.FlushContext()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
            println!("{flush_handle:#010x}");
        } else {
            return Err(TpmError::InvalidHandle(format!(
                "'{:#010x}' is not a transient or persistent handle",
                self.handle
            )));
        }
        Ok(())
    }
}
