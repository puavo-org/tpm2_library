// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli, AuthSession, SessionData, TpmError};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use json;
use serde_json;
use std::io::{BufRead, BufReader, Read, Write};
use tpm2_protocol::data::{Tpm2bAuth, Tpm2bNonce, TpmAlgId, TpmaSession};

/// Manages the streaming I/O for a command in the JSON Lines pipeline.
pub struct CommandIo<W: Write> {
    writer: W,
    input_objects: Vec<cli::Object>,
    output_objects: Vec<cli::Object>,
    pub session: Option<AuthSession>,
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
                input_objects.push(serde_json::from_str(&line)?);
            }
        }

        let mut session = None;
        let mut new_input_objects = Vec::with_capacity(input_objects.len());

        for obj in input_objects {
            if let cli::Object::Context(val) = &obj {
                if let Some(json_str) = val.as_str() {
                    if let Ok(json_val) = json::parse(json_str) {
                        if json_val["type"] == "session" {
                            let data = &json_val["data"];
                            let session_data = SessionData {
                                handle: data["handle"].as_u32().ok_or_else(|| {
                                    TpmError::Parse("session handle missing or invalid".to_string())
                                })?,
                                nonce_tpm: data["nonce_tpm"]
                                    .as_str()
                                    .ok_or_else(|| {
                                        TpmError::Parse("nonce_tpm missing or invalid".to_string())
                                    })?
                                    .to_string(),
                                attributes: data["attributes"].as_u8().ok_or_else(|| {
                                    TpmError::Parse(
                                        "session attributes missing or invalid".to_string(),
                                    )
                                })?,
                                hmac_key: data["hmac_key"]
                                    .as_str()
                                    .ok_or_else(|| {
                                        TpmError::Parse("hmac_key missing or invalid".to_string())
                                    })?
                                    .to_string(),
                                auth_hash: data["auth_hash"].as_u16().ok_or_else(|| {
                                    TpmError::Parse("auth_hash missing or invalid".to_string())
                                })?,
                                policy_digest: data["policy_digest"]
                                    .as_str()
                                    .ok_or_else(|| {
                                        TpmError::Parse(
                                            "policy_digest missing or invalid".to_string(),
                                        )
                                    })?
                                    .to_string(),
                            };
                            session = Some(AuthSession {
                                handle: session_data.handle.into(),
                                nonce_tpm: Tpm2bNonce::try_from(
                                    base64_engine.decode(session_data.nonce_tpm)?.as_slice(),
                                )?,
                                attributes: TpmaSession::from_bits_truncate(
                                    session_data.attributes,
                                ),
                                hmac_key: Tpm2bAuth::try_from(
                                    base64_engine.decode(session_data.hmac_key)?.as_slice(),
                                )?,
                                auth_hash: TpmAlgId::try_from(session_data.auth_hash).map_err(
                                    |()| {
                                        TpmError::Parse(
                                            "invalid auth_hash in session data".to_string(),
                                        )
                                    },
                                )?,
                            });
                            continue;
                        }
                    }
                }
            }
            new_input_objects.push(obj);
        }

        Ok(Self {
            writer,
            input_objects: new_input_objects,
            output_objects: Vec::new(),
            session,
            log_format,
        })
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
            let json_str = serde_json::to_string(&obj)?;
            writeln!(self.writer, "{json_str}")?;
        }
        Ok(())
    }
}
