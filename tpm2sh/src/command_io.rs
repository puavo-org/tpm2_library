// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli, from_json_str, AuthSession, SessionData, TpmError};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::io::{BufRead, BufReader, Read, Write};
use tpm2_protocol::data::{Tpm2bAuth, Tpm2bNonce, TpmAlgId, TpmaSession};

/// Manages the streaming I/O for a command in the JSON Lines pipeline.
pub struct CommandIo<W: Write> {
    writer: W,
    input_objects: Vec<cli::Object>,
    output_objects: Vec<cli::Object>,
    pub log_format: cli::LogFormat,
}

impl<W: Write> CommandIo<W> {
    /// Creates a new command context for the pipeline.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if reading from the input stream fails.
    pub fn new<R: Read>(
        reader: R,
        writer: W,
        log_format: cli::LogFormat,
    ) -> Result<Self, TpmError> {
        let mut input_objects: Vec<cli::Object> = Vec::new();
        let buf_reader = BufReader::new(reader);
        for line in buf_reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                let json_val = json::parse(&line)?;
                input_objects.push(cli::Object::from_json(&json_val)?);
            }
        }

        Ok(Self {
            writer,
            input_objects,
            output_objects: Vec::new(),
            log_format,
        })
    }

    /// Finds and removes the session object from the input pipeline, if it exists.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if an object appears to be a session but is malformed.
    pub fn take_session(&mut self) -> Result<Option<AuthSession>, TpmError> {
        let session_pos = self.input_objects.iter().position(|obj| {
            let cli::Object::TpmObject(s) = obj;
            if let Ok(val) = json::parse(s) {
                return val["type"] == "session";
            }
            false
        });

        if let Some(pos) = session_pos {
            let obj = self.input_objects.remove(pos);
            let cli::Object::TpmObject(s) = obj;
            let json_val = from_json_str(&s, "session")?;
            let session_data = SessionData::from_json(&json_val)?;
            let session = AuthSession {
                handle: session_data.handle.into(),
                nonce_tpm: Tpm2bNonce::try_from(
                    base64_engine.decode(session_data.nonce_tpm)?.as_slice(),
                )?,
                attributes: TpmaSession::from_bits_truncate(session_data.attributes),
                hmac_key: Tpm2bAuth::try_from(
                    base64_engine.decode(session_data.hmac_key)?.as_slice(),
                )?,
                auth_hash: TpmAlgId::try_from(session_data.auth_hash)
                    .map_err(|()| TpmError::Parse("invalid auth_hash in session".to_string()))?,
                original_json: s,
            };
            return Ok(Some(session));
        }

        Ok(None)
    }

    /// Finds and removes the first object from the input pipeline that matches a predicate.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if no matching object is found.
    pub fn consume_object<F>(&mut self, predicate: F) -> Result<cli::Object, TpmError>
    where
        F: FnMut(&cli::Object) -> bool,
    {
        let pos = self
            .input_objects
            .iter()
            .position(predicate)
            .ok_or_else(|| {
                TpmError::Execution("required object not found in input pipeline".to_string())
            })?;
        Ok(self.input_objects.remove(pos))
    }

    /// Adds an object to be written to the output stream upon finalization.
    pub fn push_object(&mut self, obj: cli::Object) {
        self.output_objects.push(obj);
    }

    /// Finalizes the command, writing all new and unconsumed objects to the output stream.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if JSON serialization or I/O fails.
    pub fn finalize(mut self) -> Result<(), TpmError> {
        let mut final_objects = self.input_objects;
        final_objects.append(&mut self.output_objects);

        for obj in final_objects {
            let json_str = obj.to_json().dump();
            writeln!(self.writer, "{json_str}")?;
        }
        Ok(())
    }
}
