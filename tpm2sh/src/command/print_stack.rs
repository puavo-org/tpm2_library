// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, PrintStack},
    pretty_printer::pretty_print_json_object_to_stdout,
    Command, CommandIo, TpmDevice, TpmError,
};
use lexopt::prelude::*;
use std::io;

const ABOUT: &str = "Prints a human-readable summary of the object stack to stdout";
const USAGE: &str = "tpm2sh print-stack";
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for PrintStack {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("print-stack", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        if let Some(arg) = parser.next()? {
            if arg == Short('h') || arg == Long("help") {
                if let Some(extra_arg) = parser.next()? {
                    return Err(TpmError::from(extra_arg.unexpected()));
                }
                Self::help();
                return Err(TpmError::HelpDisplayed);
            }
            return Err(TpmError::from(arg.unexpected()));
        }

        Ok(Commands::PrintStack(PrintStack::default()))
    }

    /// Runs `print-stack`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails.
    fn run(&self, _device: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError> {
        let mut io = CommandIo::new(io::stdout(), log_format)?;
        let objects = io.consume_all_objects();

        for obj in objects.iter().rev() {
            let cli::Object::TpmObject(json_str) = obj;
            let json_val = json::parse(json_str)?;

            pretty_print_json_object_to_stdout(&json_val, 0);
        }

        Ok(())
    }
}
