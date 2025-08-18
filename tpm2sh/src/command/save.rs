// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, Object, Save},
    get_auth_sessions, parse_hex_u32, parse_persistent_handle, Command, CommandIo, TpmDevice,
    TpmError,
};
use lexopt::prelude::*;
use tpm2_protocol::{data::TpmRh, message::TpmEvictControlCommand};

const ABOUT: &str = "Saves to non-volatile memory";
const USAGE: &str = "tpm2sh save [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--object-handle",
        "<HANDLE>",
        "Handle of the transient object (optional if piped)",
    ),
    (
        None,
        "--persistent-handle",
        "<HANDLE>",
        "Handle for the persistent object to be created",
    ),
    (None, "--auth", "<AUTH>", "Authorization value"),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Save {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("save", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Save::default();
        while let Some(arg) = parser.next()? {
            match arg {
                Long("object-handle") => {
                    args.object_handle = parse_hex_u32(&parser.value()?.string()?)?;
                }
                Long("persistent-handle") => {
                    args.persistent_handle = parse_persistent_handle(&parser.value()?.string()?)?;
                }
                Long("auth") => args.auth.auth = Some(parser.value()?.string()?),
                Short('h') | Long("help") => {
                    Self::help();
                    std::process::exit(0);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }
        Ok(Commands::Save(args))
    }
    /// Runs `save`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError> {
        let mut io = CommandIo::new(std::io::stdin(), std::io::stdout(), log_format)?;
        let session = io.take_session()?;

        let object_handle = if self.object_handle != 0 {
            self.object_handle
        } else {
            let obj = io.consume_object(|_| true)?;
            let Object::TpmObject(hex_string) = obj;
            parse_hex_u32(&hex_string)?
        };

        let auth_handle = TpmRh::Owner;
        let handles = [auth_handle as u32, object_handle];

        let evict_cmd = TpmEvictControlCommand {
            persistent_handle: self.persistent_handle,
        };

        let sessions = get_auth_sessions(
            &evict_cmd,
            &handles,
            session.as_ref(),
            self.auth.auth.as_deref(),
        )?;

        let (resp, _) = chip.execute(&evict_cmd, Some(&handles), &sessions, log_format)?;
        resp.EvictControl()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        let obj = Object::TpmObject(format!("{:#010x}", self.persistent_handle));
        io.push_object(obj);
        io.finalize()
    }
}
