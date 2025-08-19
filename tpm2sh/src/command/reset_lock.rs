// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, ResetLock},
    get_auth_sessions, parse_args, Command, CommandIo, TpmDevice, TpmError,
};
use lexopt::prelude::*;
use tpm2_protocol::{data::TpmRh, message::TpmDictionaryAttackLockResetCommand};

const ABOUT: &str = "Resets the dictionary attack lockout timer";
const USAGE: &str = "tpm2sh reset-lock [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (None, "--auth", "<AUTH>", "Authorization value"),
    (Some("-h"), "--help", "", "Print help information"),
];
impl Command for ResetLock {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("reset-lock", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = ResetLock::default();
        parse_args!(parser, arg, Self::help, {
            Long("auth") => {
                args.auth.auth = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        Ok(Commands::ResetLock(args))
    }

    /// Runs `reset-lock`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError> {
        let mut io = CommandIo::new(std::io::stdout(), log_format)?;
        let session = io.take_session()?;

        let command = TpmDictionaryAttackLockResetCommand {};
        let handles = [TpmRh::Lockout as u32];
        let sessions = get_auth_sessions(
            &command,
            &handles,
            session.as_ref(),
            self.auth.auth.as_deref(),
        )?;
        let (resp, _) = chip.execute(&command, Some(&handles), &sessions, log_format)?;
        resp.DictionaryAttackLockReset()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
        io.finalize()
    }
}
