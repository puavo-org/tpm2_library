// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::DeleteArgs, get_auth_sessions, AuthSession, TpmDevice, TpmError};
use tpm2_protocol::{
    data::TpmRh,
    message::{TpmEvictControlCommand, TpmFlushContextCommand},
    TpmPersistent, TpmTransient,
};

/// Executes the `delete` command.
///
/// # Errors
///
/// Returns a `TpmError` if the handle is invalid, communication with the TPM fails,
/// or if the command is improperly authorized.
pub fn run(
    chip: &mut TpmDevice,
    args: &DeleteArgs,
    session: Option<&AuthSession>,
) -> Result<(), TpmError> {
    let handle_val = u32::from_str_radix(args.handle.trim_start_matches("0x"), 16)
        .map_err(|e| TpmError::InvalidHandle(format!("'{}': {}", args.handle, e)))?;

    let handle_type = (handle_val >> 24) as u8;

    match handle_type {
        0x80 => {
            let flush_handle = TpmTransient(handle_val);
            let flush_cmd = TpmFlushContextCommand {
                flush_handle: flush_handle.into(),
            };
            let (resp, _) = chip.execute(&flush_cmd, Some(&[]), &[])?;
            resp.FlushContext()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
            println!("{flush_handle:#010x}");
        }
        0x81 => {
            let persistent_handle = TpmPersistent(handle_val);
            let auth_handle = TpmRh::Owner;
            let handles = [auth_handle as u32, persistent_handle.into()];
            let evict_cmd = TpmEvictControlCommand { persistent_handle };

            let sessions =
                get_auth_sessions(&evict_cmd, &handles, session, args.auth.auth.as_deref())?;
            let (resp, _) = chip.execute(&evict_cmd, Some(&handles), &sessions)?;
            resp.EvictControl()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
            println!("{persistent_handle:#010x}");
        }
        _ => {
            return Err(TpmError::InvalidHandle(format!(
                "'{}' is not a transient or persistent handle",
                args.handle
            )));
        }
    }
    Ok(())
}
