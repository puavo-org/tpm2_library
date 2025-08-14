// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Load, Object},
    get_auth_sessions, object_to_handle, pop_object_data, AuthSession, Command, CommandIo,
    TpmDevice, TpmError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::io;
use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic},
    message::TpmLoadCommand,
    TpmParse,
};

impl Command for Load {
    /// Runs `load`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, session: Option<&AuthSession>) -> Result<(), TpmError> {
        let mut io = CommandIo::new(io::stdin(), io::stdout(), session)?;

        let parent_obj = io.consume_object(|obj| !matches!(obj, Object::Pcrs(_)))?;
        let parent_handle = object_to_handle(chip, &parent_obj)?;

        let object_data = pop_object_data(&mut io)?;

        let pub_bytes = base64_engine
            .decode(object_data.public)
            .map_err(|e| TpmError::Parse(e.to_string()))?;
        let priv_bytes = base64_engine
            .decode(object_data.private)
            .map_err(|e| TpmError::Parse(e.to_string()))?;

        let (in_public, _) = Tpm2bPublic::parse(&pub_bytes)?;
        let (in_private, _) = Tpm2bPrivate::parse(&priv_bytes)?;

        let load_cmd = TpmLoadCommand {
            in_private,
            in_public,
        };

        let handles = [parent_handle.into()];
        let sessions = get_auth_sessions(
            &load_cmd,
            &handles,
            io.session,
            self.parent_auth.auth.as_deref(),
        )?;

        let (resp, _) = chip.execute(&load_cmd, Some(&handles), &sessions)?;
        let load_resp = resp
            .Load()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        let new_object = crate::cli::Object::Handle(load_resp.object_handle);
        io.push_object(new_object);

        io.finalize()
    }
}
