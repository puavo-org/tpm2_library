// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{self, Commands, PcrEvent},
    get_auth_sessions, input_to_bytes, parse_args, parse_hex_u32, Command, CommandIo, TpmDevice,
    TpmError,
};
use lexopt::prelude::*;
use std::io::Write;
use tpm2_protocol::{data::Tpm2bEvent, message::TpmPcrEventCommand};

const ABOUT: &str = "Extends a PCR with an event";
const USAGE: &str = "tpm2sh pcr-event [OPTIONS] <DATA>";
const ARGS: &[CommandLineArgument] = &[(
    "DATA",
    "The data must be prefixed with 'str:', 'hex:', or 'file:'",
)];
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--pcr-handle",
        "<HANDLE>",
        "Handle of the PCR to extend",
    ),
    (None, "--auth", "<AUTH>", "Authorization value"),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for PcrEvent {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("pcr-event", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = PcrEvent::default();
        let mut data_arg = None;
        parse_args!(parser, arg, Self::help, {
            Long("pcr-handle") => {
                args.pcr_handle = parse_hex_u32(&parser.value()?.string()?)?;
            }
            Long("auth") => {
                args.auth.auth = Some(parser.value()?.string()?);
            }
            Value(val) if data_arg.is_none() => {
                data_arg = Some(val.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });

        if let Some(data) = data_arg {
            args.data = data;
            Ok(Commands::PcrEvent(args))
        } else {
            Self::help();
            Err(TpmError::HelpDisplayed)
        }
    }

    /// Runs `pcr-event`.
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
        let mut io = CommandIo::new(std::io::stdout(), log_format)?;
        let session = io.take_session()?;

        if session.is_none() && self.auth.auth.is_none() {
            return Err(TpmError::Usage(
                "Authorization is required for pcr-event. Use --auth or pipeline session."
                    .to_string(),
            ));
        }

        let handles = [self.pcr_handle];

        let data_bytes = input_to_bytes(&self.data)?;
        let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())?;
        let command = TpmPcrEventCommand {
            pcr_handle: self.pcr_handle,
            event_data,
        };

        let sessions = get_auth_sessions(
            &command,
            &handles,
            session.as_ref(),
            self.auth.auth.as_deref(),
        )?;
        let (resp, _) = chip.execute(&command, &sessions, log_format)?;
        resp.PcrEvent()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        writeln!(io.writer(), "{:#010x}", self.pcr_handle)?;

        io.finalize()
    }
}
