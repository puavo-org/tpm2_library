// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

pub mod arg_parser;
pub mod cli;
pub mod command;
pub mod command_io;
pub mod crypto;
pub mod device;
pub mod error;
pub mod formats;
pub mod key;
pub mod pcr;
pub mod pretty_printer;
pub mod session;
pub mod util;

pub use self::arg_parser::parse_cli;
pub use self::command_io::CommandIo;
pub use self::crypto::*;
pub use self::device::*;
pub use self::error::TpmError;
pub use self::formats::*;
pub use self::key::*;
pub use self::pcr::*;
pub use self::pretty_printer::PrettyTrace;
pub use self::session::*;
pub use self::util::*;

/// A trait for parsing and executing subcommands.
pub trait Command {
    /// Prints the help message for a subcommand.
    fn help()
    where
        Self: Sized;

    /// Parses the arguments for a subcommand.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on parsing failure.
    fn parse(parser: &mut lexopt::Parser) -> Result<cli::Commands, TpmError>
    where
        Self: Sized;

    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, device: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError>;
}

/// Parses command-line arguments and executes the corresponding command.
///
/// # Errors
///
/// Returns a `TpmError` if opening the device, or executing the command fails.
pub fn execute_cli() -> Result<(), TpmError> {
    let Some(cli) = parse_cli()? else {
        return Ok(());
    };

    if let Some(command) = cli.command {
        let mut device = TpmDevice::new(&cli.device)?;
        command.run(&mut device, cli.log_format)
    } else {
        Ok(())
    }
}
