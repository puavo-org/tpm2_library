// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, Unseal},
    get_auth_sessions, parse_parent_handle_from_json, pop_object_data, with_loaded_object, Command,
    CommandIo, TpmDevice, TpmError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use std::io::{self, IsTerminal, Write};
use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic},
    message::TpmUnsealCommand,
    TpmParse,
};

const ABOUT: &str = "Unseals a keyedhash object";
const USAGE: &str = "tpm2sh unseal [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (None, "--auth", "<AUTH>", "Authorization value"),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Unseal {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("unseal", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Unseal::default();
        while let Some(arg) = parser.next()? {
            match arg {
                Long("auth") => args.auth.auth = Some(parser.value()?.string()?),
                Short('h') | Long("help") => {
                    Self::help();
                    return Err(TpmError::HelpDisplayed);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }
        Ok(Commands::Unseal(args))
    }

    /// Runs `unseal`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError> {
        if std::io::stdin().is_terminal() {
            Self::help();
            std::process::exit(1);
        }

        let mut io = CommandIo::new(io::stdin(), io::stdout(), log_format)?;
        let session = io.take_session()?;
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
            session.as_ref(),
            in_public,
            in_private,
            log_format,
            |chip, object_handle| {
                let unseal_cmd = TpmUnsealCommand {};
                let unseal_handles = [object_handle.into()];
                let sessions = get_auth_sessions(
                    &unseal_cmd,
                    &unseal_handles,
                    session.as_ref(),
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
