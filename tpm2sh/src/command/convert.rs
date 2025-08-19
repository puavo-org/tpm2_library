// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, Convert, KeyFormat},
    from_json_str, Command, Envelope, ObjectData, TpmDevice, TpmError, TpmKey,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use std::{
    fs::File,
    io::{self, Read, Write},
};

const ABOUT: &str = "Converts keys between ASN.1 and JSON format";
const USAGE: &str = "tpm2sh convert [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--from",
        "<FORMAT>",
        "Input format [default: json, possible: json, pem, der]",
    ),
    (
        None,
        "--to",
        "<FORMAT>",
        "Output format [default: pem, possible: json, pem, der]",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

/// Parses a JSON string into an intermediate `TpmKey` representation.
fn json_to_tpm_key(json_str: &str) -> Result<TpmKey, TpmError> {
    let json_value = from_json_str(json_str, "object")?;
    let data = ObjectData::from_json(&json_value)?;

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
        pub_key: base64_engine.decode(data.public)?,
        priv_key: base64_engine.decode(data.private)?,
    })
}

/// Converts an intermediate `TpmKey` into a final enveloped JSON string.
fn tpm_key_to_json_string(key: TpmKey) -> String {
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
        data: data.to_json(),
    };
    envelope.to_json().pretty(2)
}

fn read_all(path: Option<&str>) -> Result<Vec<u8>, TpmError> {
    let mut buf = Vec::new();
    match path {
        Some("-") | None => {
            io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| TpmError::File("stdin".to_string(), e))?;
        }
        Some(file_path) => {
            File::open(file_path)
                .and_then(|mut f| f.read_to_end(&mut buf))
                .map_err(|e| TpmError::File(file_path.to_string(), e))?;
        }
    }
    Ok(buf)
}

impl Command for Convert {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("convert", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Convert::default();
        while let Some(arg) = parser.next()? {
            match arg {
                Long("from") => args.from = parser.value()?.string()?.parse()?,
                Long("to") => args.to = parser.value()?.string()?.parse()?,
                Short('h') | Long("help") => {
                    Self::help();
                    return Err(TpmError::HelpDisplayed);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }
        Ok(Commands::Convert(args))
    }

    /// Runs `convert`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, _device: &mut TpmDevice, _log_format: cli::LogFormat) -> Result<(), TpmError> {
        let input = read_all(None)?;
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
                println!("{}", tpm_key_to_json_string(key));
            }
            (KeyFormat::Der, KeyFormat::Json) => {
                let key = TpmKey::from_der(&input)?;
                println!("{}", tpm_key_to_json_string(key));
            }
            (from, to) if from == to => {
                io::stdout().write_all(&input)?;
            }
            _ => {
                return Err(TpmError::Usage(
                    "unsupported conversion direction".to_string(),
                ));
            }
        }
        Ok(())
    }
}
