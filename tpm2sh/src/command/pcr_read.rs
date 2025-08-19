// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{self, Commands, Object, PcrRead},
    get_pcr_count, parse_pcr_selection, pcr_response_to_output, Command, Envelope, TpmDevice,
    TpmError,
};
use lexopt::prelude::*;
use std::io::IsTerminal;
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

        let pcr_output = pcr_response_to_output(&pcr_read_resp)?;
        let envelope = Envelope {
            version: 1,
            object_type: "pcr-values".to_string(),
            data: pcr_output.to_json(),
        };

        let final_json = envelope.to_json();
        if std::io::stdout().is_terminal() {
            println!("{}", final_json.dump());
        } else {
            let pipe_obj = Object::TpmObject(final_json.dump());
            println!("{}", pipe_obj.to_json().dump());
        }

        Ok(())
    }
}
