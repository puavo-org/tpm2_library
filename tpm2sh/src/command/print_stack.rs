// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, PrintStack},
    parse_args,
    pretty_printer::pretty_print_json_object_to_stdout,
    Command, CommandIo, TpmDevice, TpmError,
};
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
        parse_args!(parser, arg, Self::help, {
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        Ok(Commands::PrintStack(PrintStack::default()))
    }

    fn is_local(&self) -> bool {
        true
    }

    /// Runs `print-stack`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails.
    fn run(
        &self,
        _device: &mut Option<TpmDevice>,
        log_format: cli::LogFormat,
    ) -> Result<(), TpmError> {
        let mut io = CommandIo::new(io::stdout(), log_format)?;
        let objects = io.consume_all_objects();

        if objects.is_empty() {
            Self::help();
            return Err(TpmError::Usage(
                "print-stack requires piped input".to_string(),
            ));
        }

        for obj in objects.iter().rev() {
            let cli::Object::TpmObject(json_str) = obj;
            let envelope = json::parse(json_str)?;

            pretty_print_json_object_to_stdout(&envelope, 0);
        }

        Ok(())
    }
}
