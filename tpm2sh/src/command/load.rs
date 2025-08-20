// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, Load},
    get_auth_sessions, parse_args,
    util::{consume_and_get_parent_handle, pop_object_data},
    Command, CommandIo, TpmDevice, TpmError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use log::warn;
use std::io::{self, IsTerminal};
use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic},
    message::{TpmFlushContextCommand, TpmLoadCommand},
    TpmParse,
};

const ABOUT: &str = "Loads a TPM key";
const USAGE: &str = "tpm2sh load [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--auth",
        "<AUTH>",
        "Authorization for the parent object",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Load {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("load", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Load::default();
        parse_args!(parser, arg, Self::help, {
            Long("auth") => {
                args.parent_auth.auth = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        Ok(Commands::Load(args))
    }

    /// Runs `load`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(
        &self,
        device: &mut Option<TpmDevice>,
        log_format: cli::LogFormat,
    ) -> Result<(), TpmError> {
        let chip = device.as_mut().unwrap();
        if std::io::stdin().is_terminal() {
            Self::help();
            std::process::exit(1);
        }

        let mut io = CommandIo::new(io::stdout(), log_format)?;
        let session = io.take_session()?;
        let (parent_handle, needs_flush) =
            consume_and_get_parent_handle(&mut io, chip, log_format)?;
        let result = (|| {
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
                session.as_ref(),
                self.parent_auth.auth.as_deref(),
            )?;

            let (resp, _) = chip.execute(&load_cmd, Some(&handles), &sessions, log_format)?;
            let load_resp = resp
                .Load()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

            let new_object = cli::Object::TpmObject(format!("{:#010x}", load_resp.object_handle));
            io.push_object(new_object);

            io.finalize()
        })();

        if needs_flush {
            let flush_cmd = TpmFlushContextCommand {
                flush_handle: parent_handle.into(),
            };
            if let Err(flush_err) = chip.execute(&flush_cmd, Some(&[]), &[], log_format) {
                warn!(
                    "Failed to flush transient parent handle {parent_handle:#010x} after operation: {flush_err}"
                );
                if result.is_ok() {
                    return Err(flush_err);
                }
            }
        }

        result
    }
}
