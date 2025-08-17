// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli,
    cli::{Commands, Object, PcrRead},
    formats::PcrOutput,
    get_pcr_count, parse_pcr_selection, tpm_alg_id_to_str, Command, TpmDevice, TpmError,
};
use lexopt::prelude::*;
use std::collections::BTreeMap;
use tpm2_protocol::message::TpmPcrReadCommand;

const ABOUT: &str = "Reads PCRs";
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
        let selection = parser.value()?.string()?;
        if let Some(arg) = parser.next()? {
            match arg {
                Short('h') | Long("help") => {
                    Self::help();
                    std::process::exit(0);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }
        Ok(Commands::PcrRead(PcrRead { selection }))
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

        let mut banks: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut pcr_iter = pcr_read_resp.pcr_values.iter();

        for selection in pcr_read_resp.pcr_selection_out.iter() {
            let bank = banks
                .entry(tpm_alg_id_to_str(selection.hash).to_string())
                .or_default();
            for (byte_index, &byte) in selection.pcr_select.iter().enumerate() {
                for bit_index in 0..8 {
                    if (byte >> bit_index) & 1 == 1 {
                        let pcr_index = byte_index * 8 + bit_index;
                        if let Some(digest) = pcr_iter.next() {
                            bank.insert(pcr_index.to_string(), hex::encode_upper(digest.as_ref()));
                        }
                    }
                }
            }
        }

        let pcr_output = PcrOutput {
            update_counter: pcr_read_resp.pcr_update_counter,
            banks,
        };

        let output_object = Object::Pcrs(pcr_output);
        let json_line = output_object.to_json().dump();
        println!("{json_line}");

        Ok(())
    }
}
