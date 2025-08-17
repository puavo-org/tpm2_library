// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{self, Commands, PrintError},
    parse_tpm_rc, Command, TpmDevice, TpmError,
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
        let rc_str = parser.value()?.string()?;
        if let Some(arg) = parser.next()? {
            match arg {
                Short('h') | Long("help") => {
                    Self::help();
                    std::process::exit(0);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }
        Ok(Commands::PrintError(PrintError {
            rc: parse_tpm_rc(&rc_str)?,
        }))
    }

    fn run(&self, _device: &mut TpmDevice, _log_format: cli::LogFormat) -> Result<(), TpmError> {
        println!("{}", self.rc);
        Ok(())
    }
}
