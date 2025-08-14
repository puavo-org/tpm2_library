// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::Delete, get_auth_sessions, AuthSession, Command, TpmDevice, TpmError};
use tpm2_protocol::{
    data::TpmRh,
    message::{TpmEvictControlCommand, TpmFlushContextCommand},
    TpmPersistent, TpmTransient,
};

impl Command for Delete {
    /// Runs `delete`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, session: Option<&AuthSession>) -> Result<(), TpmError> {
        let handle_type = (self.handle >> 24) as u8;

        match handle_type {
            0x80 => {
                let flush_handle = TpmTransient(self.handle);
                let flush_cmd = TpmFlushContextCommand {
                    flush_handle: flush_handle.into(),
                };
                let (resp, _) = chip.execute(&flush_cmd, Some(&[]), &[])?;
                resp.FlushContext()
                    .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
                println!("{flush_handle:#010x}");
            }
            0x81 => {
                let persistent_handle = TpmPersistent(self.handle);
                let auth_handle = TpmRh::Owner;
                let handles = [auth_handle as u32, persistent_handle.into()];
                let evict_cmd = TpmEvictControlCommand { persistent_handle };

                let sessions =
                    get_auth_sessions(&evict_cmd, &handles, session, self.auth.auth.as_deref())?;
                let (resp, _) = chip.execute(&evict_cmd, Some(&handles), &sessions)?;
                resp.EvictControl()
                    .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
                println!("{persistent_handle:#010x}");
            }
            _ => {
                return Err(TpmError::InvalidHandle(format!(
                    "'{:#010x}' is not a transient or persistent handle",
                    self.handle
                )));
            }
        }
        Ok(())
    }
}
