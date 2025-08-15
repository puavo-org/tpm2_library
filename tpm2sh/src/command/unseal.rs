// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli, cli::Unseal, get_auth_sessions, parse_parent_handle_from_json, pop_object_data,
    with_loaded_object, AuthSession, Command, CommandIo, TpmDevice, TpmError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::io::{self, Write};
use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic},
    message::TpmUnsealCommand,
    TpmParse,
};

impl Command for Unseal {
    /// Runs `unseal`.
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
        let mut io = CommandIo::new(io::stdin(), io::stdout(), session, log_format)?;
        let object_data = pop_object_data(&mut io)?;

        let parent_handle = parse_parent_handle_from_json(&object_data)?;

        let pub_bytes = base64_engine
            .decode(object_data.public)
            .map_err(|e| TpmError::Parse(e.to_string()))?;
        let priv_bytes = base64_engine
            .decode(object_data.private)
            .map_err(|e| TpmError::Parse(e.to_string()))?;

        let (in_public, _) = Tpm2bPublic::parse(&pub_bytes)?;
        let (in_private, _) = Tpm2bPrivate::parse(&priv_bytes)?;

        let output = with_loaded_object(
            chip,
            parent_handle,
            &self.auth,
            io.session,
            in_public,
            in_private,
            log_format,
            |chip, object_handle| {
                let unseal_cmd = TpmUnsealCommand {};
                let unseal_handles = [object_handle.into()];
                let sessions = get_auth_sessions(
                    &unseal_cmd,
                    &unseal_handles,
                    io.session,
                    self.auth.auth.as_deref(),
                )?;

                let (unseal_resp, _) =
                    chip.execute(&unseal_cmd, Some(&unseal_handles), &sessions, log_format)?;

                let unseal_resp = unseal_resp
                    .Unseal()
                    .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

                Ok(unseal_resp.out_data.to_vec())
            },
        )?;

        io::stdout().write_all(&output)?;

        io.finalize()
    }
}
