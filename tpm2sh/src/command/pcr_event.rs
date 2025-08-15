// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli, cli::PcrEvent, get_auth_sessions, AuthSession, Command, TpmDevice, TpmError};
use tpm2_protocol::{data::Tpm2b, message::TpmPcrEventCommand};

impl Command for PcrEvent {
    /// Runs `pcr-event`.
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
        if session.is_none() && self.auth.auth.is_none() {
            return Err(TpmError::Execution(
                "Authorization is required for pcr-event. Use --auth or --session.".to_string(),
            ));
        }

        let handles = [self.pcr_handle];

        let event_data = Tpm2b::try_from(self.data.as_bytes())?;
        let command = TpmPcrEventCommand { event_data };

        let sessions = get_auth_sessions(&command, &handles, session, self.auth.auth.as_deref())?;

        let (resp, _) = chip.execute(&command, Some(&handles), &sessions, log_format)?;
        resp.PcrEvent()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        println!("{:#010x}", self.pcr_handle);
        Ok(())
    }
}
