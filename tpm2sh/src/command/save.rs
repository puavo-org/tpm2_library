// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{self, Commands, Object, Save},
    get_auth_sessions, parse_args, parse_hex_u32, parse_persistent_handle, Command, CommandIo,
    TpmDevice, TpmError,
};
use lexopt::prelude::*;
use std::io::IsTerminal;
use tpm2_protocol::{data::TpmRh, message::TpmEvictControlCommand};

const ABOUT: &str = "Saves to non-volatile memory";
const USAGE: &str = "tpm2sh save [OPTIONS] <FROM> <TO>";
const ARGS: &[CommandLineArgument] = &[
    ("FROM", "Handle of the transient object ('-' for stdin)"),
    ("TO", "Handle for the persistent object to be created"),
];
const OPTIONS: &[CommandLineOption] = &[
    (None, "--password", "<PASSWORD>", "Authorization value"),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Save {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("save", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Save::default();
        let mut from_arg = None;
        let mut to_arg = None;

        parse_args!(parser, arg, Self::help, {
            Long("password") => {
                args.password.password = Some(parser.value()?.string()?);
            }
            Value(val) if from_arg.is_none() => {
                from_arg = Some(val.string()?);
            }
            Value(val) if to_arg.is_none() => {
                to_arg = Some(val.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });

        if let (Some(from), Some(to)) = (from_arg, to_arg) {
            args.from = from;
            args.to = to;
            Ok(Commands::Save(args))
        } else {
            Self::help();
            Err(TpmError::HelpDisplayed)
        }
    }
    /// Runs `save`.
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
        if self.from.is_empty() && std::io::stdin().is_terminal() {
            Self::help();
            return Err(TpmError::HelpDisplayed);
        }

        let mut io = CommandIo::new(std::io::stdout(), log_format)?;
        let session = io.take_session()?;
        let object_handle = if self.from == "-" {
            let obj = io.consume_object(|_| true)?;
            let Object::TpmObject(hex_string) = obj;
            parse_hex_u32(&hex_string)?
        } else {
            parse_hex_u32(&self.from)?
        };

        let persistent_handle = parse_persistent_handle(&self.to)?;
        let auth_handle = TpmRh::Owner;
        let handles = [auth_handle as u32, object_handle];
        let evict_cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: object_handle.into(),
            persistent_handle,
        };
        let sessions = get_auth_sessions(
            &evict_cmd,
            &handles,
            session.as_ref(),
            self.password.password.as_deref(),
        )?;
        let (resp, _) = chip.execute(&evict_cmd, &sessions, log_format)?;
        resp.EvictControl()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
        let obj = Object::TpmObject(format!("{persistent_handle:#010x}"));
        io.push_object(obj);
        io.finalize()
    }
}
