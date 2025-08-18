// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    build_to_vec,
    cli::{self, Commands, Object, PcrRead},
    get_pcr_count, parse_pcr_selection, Command, TpmDevice, TpmError,
};
use lexopt::prelude::*;
use tpm2_protocol::message::TpmPcrReadCommand;

const ABOUT: &str = "Reads PCR values from the TPM";
const USAGE: &str = "tpm2sh pcr-read <SELECTION>";
const ARGS: &[CommandLineArgument] = &[("SELECTION", "e.g. 'sha256:0,1,2+sha1:0'")];
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for PcrRead {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("pcr-read", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut selection = None;

        while let Some(arg) = parser.next()? {
            match arg {
                Short('h') | Long("help") => {
                    Self::help();
                    return Err(TpmError::HelpDisplayed);
                }
                Value(val) if selection.is_none() => {
                    selection = Some(val.string()?);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }

        if let Some(selection) = selection {
            Ok(Commands::PcrRead(PcrRead { selection }))
        } else {
            Self::help();
            Err(TpmError::HelpDisplayed)
        }
    }

    /// Runs `pcr-read`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError> {
        let pcr_count = get_pcr_count(chip, log_format)?;
        let pcr_selection_in = parse_pcr_selection(&self.selection, pcr_count)?;

        let cmd = TpmPcrReadCommand { pcr_selection_in };
        let (resp, _) = chip.execute(&cmd, None, &[], log_format)?;
        let pcr_read_resp = resp
            .PcrRead()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        let response_bytes = build_to_vec(&pcr_read_resp)?;
        let obj = Object::TpmObject(hex::encode(response_bytes));
        println!("{}", obj.to_json().dump());

        Ok(())
    }
}
