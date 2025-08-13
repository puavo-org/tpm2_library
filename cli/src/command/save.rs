// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::SaveArgs, get_auth_sessions, AuthSession, TpmDevice, TpmError};
use tpm2_protocol::{data::TpmRh, message::TpmEvictControlCommand};

/// Executes the `save` command to make a transient object persistent.
///
/// # Errors
///
/// Returns a `TpmError` if communication with the TPM fails or if the command
/// is improperly authorized.
pub fn run(
    chip: &mut TpmDevice,
    args: &SaveArgs,
    session: Option<&AuthSession>,
) -> Result<(), TpmError> {
    let auth_handle = TpmRh::Owner;
    let handles = [auth_handle as u32, args.object_handle];

    let evict_cmd = TpmEvictControlCommand {
        persistent_handle: args.persistent_handle,
    };

    let sessions = get_auth_sessions(&evict_cmd, &handles, session, args.auth.auth.as_deref())?;

    let (resp, _) = chip.execute(&evict_cmd, Some(&handles), &sessions)?;
    resp.EvictControl()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

    println!("{:#010x}", args.persistent_handle);
    Ok(())
}
