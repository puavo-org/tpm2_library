// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::PcrEventArgs, get_auth_sessions, AuthSession, TpmDevice, TpmError};
use tpm2_protocol::{data::Tpm2b, message::TpmPcrEventCommand};

/// Executes the `pcr-event` command.
///
/// # Errors
///
/// Returns a `TpmError` if authorization is missing, if communication with the
/// TPM fails, or if the command is improperly authorized.
pub fn run(
    chip: &mut TpmDevice,
    args: &PcrEventArgs,
    session: Option<&AuthSession>,
) -> Result<(), TpmError> {
    if session.is_none() && args.auth.auth.is_none() {
        return Err(TpmError::Execution(
            "Authorization is required for pcr-event. Use --auth or --session.".to_string(),
        ));
    }

    let handles = [args.pcr_handle];

    let event_data = Tpm2b::try_from(args.data.as_bytes())?;
    let command = TpmPcrEventCommand { event_data };

    let sessions = get_auth_sessions(&command, &handles, session, args.auth.auth.as_deref())?;

    let (resp, _) = chip.execute(&command, Some(&handles), &sessions)?;
    resp.PcrEvent()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

    println!("{:#010x}", args.pcr_handle);
    Ok(())
}
