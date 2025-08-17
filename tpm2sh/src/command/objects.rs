// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, Objects},
    Command, TpmDevice, TpmError,
};
use lexopt::prelude::*;
use tpm2_protocol::{data::TpmRh, TpmPersistent, TpmTransient};

const ABOUT: &str = "Lists objects in volatile and non-volatile memory";
const USAGE: &str = "tpm2sh objects";
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for Objects {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("objects", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        if let Some(arg) = parser.next()? {
            match arg {
                Short('h') | Long("help") => {
                    Self::help();
                    std::process::exit(0);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }
        Ok(Commands::Objects(Objects {}))
    }

    /// Runs `objects`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, device: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError> {
        let transient_handles = cli::get_handles(device, TpmRh::TransientFirst, log_format)?;
        for handle in transient_handles {
            let obj = cli::Object::Handle(TpmTransient(handle));
            let json_line = obj.to_json().dump();
            println!("{json_line}");
        }

        let persistent_handles = cli::get_handles(device, TpmRh::PersistentFirst, log_format)?;
        for handle in persistent_handles {
            let obj = cli::Object::Persistent(TpmPersistent(handle));
            let json_line = obj.to_json().dump();
            println!("{json_line}");
        }

        Ok(())
    }
}
