// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::KeyFormat, from_json_str, read_input, AuthSession, Command, Envelope, ObjectData,
    TpmDevice, TpmError, TpmKey,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::io::{self, Write};

/// Parses a JSON string into an intermediate `TpmKey` representation.
fn json_to_tpm_key(json_str: &str) -> Result<TpmKey, TpmError> {
    let data: ObjectData = from_json_str(json_str, "object")?;
    Ok(TpmKey {
        oid: data
            .oid
            .split('.')
            .map(|s| {
                s.parse::<u32>()
                    .map_err(|_| TpmError::Parse("invalid OID arc".to_string()))
            })
            .collect::<Result<_, _>>()?,
        parent: data.parent,
        pub_key: base64_engine
            .decode(data.public)
            .map_err(|e| TpmError::Parse(e.to_string()))?,
        priv_key: base64_engine
            .decode(data.private)
            .map_err(|e| TpmError::Parse(e.to_string()))?,
    })
}

/// Converts an intermediate `TpmKey` into a final enveloped JSON string.
fn tpm_key_to_json_string(key: TpmKey) -> Result<String, TpmError> {
    let data = ObjectData {
        oid: key
            .oid
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("."),
        empty_auth: false,
        parent: key.parent,
        public: base64_engine.encode(key.pub_key),
        private: base64_engine.encode(key.priv_key),
    };
    let envelope = Envelope {
        version: 1,
        object_type: "object".to_string(),
        data: serde_json::to_value(data)?,
    };
    serde_json::to_string_pretty(&envelope).map_err(Into::into)
}

impl Command for crate::cli::Convert {
    /// Runs `convert`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, _device: &mut TpmDevice, _session: Option<&AuthSession>) -> Result<(), TpmError> {
        let input = read_input(None)?;
        match (self.from, self.to) {
            (KeyFormat::Json, KeyFormat::Pem) => {
                let json_str =
                    String::from_utf8(input).map_err(|e| TpmError::Parse(e.to_string()))?;
                let key = json_to_tpm_key(&json_str)?;
                println!("{}", key.to_pem()?);
            }
            (KeyFormat::Json, KeyFormat::Der) => {
                let json_str =
                    String::from_utf8(input).map_err(|e| TpmError::Parse(e.to_string()))?;
                let key = json_to_tpm_key(&json_str)?;
                io::stdout().write_all(&key.to_der()?)?;
            }
            (KeyFormat::Pem, KeyFormat::Json) => {
                let key = TpmKey::from_pem(&input)?;
                println!("{}", tpm_key_to_json_string(key)?);
            }
            (KeyFormat::Der, KeyFormat::Json) => {
                let key = TpmKey::from_der(&input)?;
                println!("{}", tpm_key_to_json_string(key)?);
            }
            (from, to) if from == to => {
                io::stdout().write_all(&input)?;
            }
            _ => {
                return Err(TpmError::Execution(
                    "unsupported conversion direction".to_string(),
                ));
            }
        }
        Ok(())
    }
}
