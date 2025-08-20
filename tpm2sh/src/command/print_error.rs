// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{self, Commands, PrintError},
    parse_args, parse_tpm_rc, Command, TpmDevice, TpmError,
};
use lexopt::prelude::*;

const ABOUT: &str = "Encodes and print a TPM error code";
const USAGE: &str = "tpm2sh print-error <RC>";
const ARGS: &[CommandLineArgument] = &[("<RC>", "TPM error code")];
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for PrintError {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("print-error", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut rc_str: Option<String> = None;
        parse_args!(parser, arg, Self::help, {
            Value(val) if rc_str.is_none() => {
                rc_str = Some(val.string()?);
            }
            _ => return Err(TpmError::from(arg.unexpected())),
        });

        if let Some(s) = rc_str {
            Ok(Commands::PrintError(PrintError {
                rc: parse_tpm_rc(&s)?,
            }))
        } else {
            Self::help();
            Err(TpmError::HelpDisplayed)
        }
    }

    fn is_local(&self) -> bool {
        true
    }

    fn run(
        &self,
        _device: &mut Option<TpmDevice>,
        _log_format: cli::LogFormat,
    ) -> Result<(), TpmError> {
        println!("{}", self.rc);
        Ok(())
    }
}
