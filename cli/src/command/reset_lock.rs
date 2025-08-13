// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::ResetLockArgs, get_auth_sessions, AuthSession, TpmDevice, TpmError};
use tpm2_protocol::{data::TpmRh, message::TpmDictionaryAttackLockResetCommand};

/// Executes the `reset-lock` command.
///
/// # Errors
///
/// Returns a `TpmError` if communication with the TPM fails or if the command
/// is improperly authorized.
pub fn run(
    chip: &mut TpmDevice,
    args: &ResetLockArgs,
    session: Option<&AuthSession>,
) -> Result<(), TpmError> {
    let command = TpmDictionaryAttackLockResetCommand {};
    let handles = [TpmRh::Lockout as u32];

    let sessions = get_auth_sessions(&command, &handles, session, args.auth.auth.as_deref())?;

    let (resp, _) = chip.execute(&command, Some(&handles), &sessions)?;
    resp.DictionaryAttackLockReset()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

    Ok(())
}
