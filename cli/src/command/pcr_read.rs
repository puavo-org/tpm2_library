// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::PcrRead, tpm_alg_id_from_str, AuthSession, Command, TpmDevice, TpmError,
    TPM_CAP_PROPERTY_MAX,
};
use std::collections::BTreeMap;
use tpm2_protocol::{
    data::{
        TpmAlgId, TpmCap, TpmlPcrSelection, TpmsPcrSelection, TpmuCapabilities, TPM_PCR_SELECT_MAX,
    },
    message::{TpmGetCapabilityCommand, TpmPcrReadCommand},
    TpmBuffer,
};

fn get_pcr_count(chip: &mut TpmDevice) -> Result<usize, TpmError> {
    let get_pcr_cap = TpmGetCapabilityCommand {
        cap: TpmCap::Pcrs,
        property: 0,
        property_count: TPM_CAP_PROPERTY_MAX,
    };

    let (resp, _) = chip.execute(&get_pcr_cap, None, &[])?;

    let pcr_cap = resp
        .GetCapability()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

    if let TpmuCapabilities::Pcrs(pcrs) = pcr_cap.capability_data.data {
        if let Some(first_bank) = pcrs.iter().next() {
            Ok(first_bank.pcr_select.len() * 8)
        } else {
            Err(TpmError::Execution(
                "TPM reported no active PCR banks.".to_string(),
            ))
        }
    } else {
        Err(TpmError::Execution(
            "Unexpected capability data type when querying for PCRs.".to_string(),
        ))
    }
}

fn parse_pcr_selection(
    selection_str: &str,
    pcr_count: usize,
) -> Result<TpmlPcrSelection, TpmError> {
    let pcr_select_size = pcr_count.div_ceil(8);
    if pcr_select_size > TPM_PCR_SELECT_MAX {
        return Err(TpmError::PcrSelection(format!(
            "required pcr select size {pcr_select_size} exceeds maximum {TPM_PCR_SELECT_MAX}"
        )));
    }

    let mut list = TpmlPcrSelection::new();
    for bank_str in selection_str.split('+') {
        let (alg_str, pcrs_str) = bank_str
            .split_once(':')
            .ok_or_else(|| TpmError::PcrSelection(format!("invalid bank format: {bank_str}")))?;

        let alg: TpmAlgId = tpm_alg_id_from_str(alg_str).map_err(TpmError::PcrSelection)?;

        let mut pcr_select_bytes = [0u8; TPM_PCR_SELECT_MAX];
        for pcr_str in pcrs_str.split(',') {
            let pcr_index: usize = pcr_str
                .parse()
                .map_err(|_| TpmError::PcrSelection(format!("invalid pcr index: {pcr_str}")))?;
            if pcr_index >= pcr_count {
                return Err(TpmError::PcrSelection(format!(
                    "pcr index {pcr_index} is out of range for a TPM with {pcr_count} PCRs"
                )));
            }
            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }

        list.try_push(TpmsPcrSelection {
            hash: alg,
            pcr_select: TpmBuffer::try_from(&pcr_select_bytes[..pcr_select_size])?,
        })?;
    }
    Ok(list)
}

impl Command for PcrRead {
    /// Runs `pcr-read`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, _session: Option<&AuthSession>) -> Result<(), TpmError> {
        let pcr_count = get_pcr_count(chip)?;
        let pcr_selection_in = parse_pcr_selection(&self.selection, pcr_count)?;

        let cmd = TpmPcrReadCommand { pcr_selection_in };
        let (resp, _) = chip.execute(&cmd, None, &[])?;

        let pcr_read_resp = resp
            .PcrRead()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        let mut pcr_map: BTreeMap<TpmAlgId, BTreeMap<usize, Vec<u8>>> = BTreeMap::new();
        let mut pcr_iter = pcr_read_resp.pcr_values.iter();

        for selection in pcr_read_resp.pcr_selection_out.iter() {
            let bank = pcr_map.entry(selection.hash).or_default();
            for (byte_index, &byte) in selection.pcr_select.iter().enumerate() {
                for bit_index in 0..8 {
                    if (byte >> bit_index) & 1 == 1 {
                        let pcr_index = byte_index * 8 + bit_index;
                        if let Some(digest) = pcr_iter.next() {
                            bank.insert(pcr_index, digest.to_vec());
                        }
                    }
                }
            }
        }

        println!("pcr-update-counter: {}", pcr_read_resp.pcr_update_counter);

        for (alg, pcrs) in &pcr_map {
            println!("{alg}:");
            for (pcr_index, digest) in pcrs {
                println!("  {:02}: {}", pcr_index, hex::encode_upper(digest));
            }
        }

        Ok(())
    }
}
