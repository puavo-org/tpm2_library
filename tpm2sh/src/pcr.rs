// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli, device, TpmDevice, TpmError};
use pest::Parser as PestParser;
use pest_derive::Parser;
use std::str::FromStr;
use tpm2_protocol::data;

#[derive(Parser)]
#[grammar = "command/pcr_selection.pest"]
pub struct PcrSelectionParser;

/// Gets the number of PCRs from the TPM.
pub(crate) fn get_pcr_count(
    chip: &mut TpmDevice,
    log_format: cli::LogFormat,
) -> Result<usize, TpmError> {
    let cap_data = chip.get_capability(
        data::TpmCap::Pcrs,
        0,
        device::TPM_CAP_PROPERTY_MAX,
        log_format,
    )?;
    let Some(first_cap) = cap_data.into_iter().next() else {
        return Err(TpmError::Execution(
            "TPM reported no capabilities for PCRs.".to_string(),
        ));
    };

    if let data::TpmuCapabilities::Pcrs(pcrs) = first_cap.data {
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

/// Parses a PCR selection string (e.g., "sha256:0,7+sha1:1") into a TPM list.
pub(crate) fn parse_pcr_selection(
    selection_str: &str,
    pcr_count: usize,
) -> Result<data::TpmlPcrSelection, TpmError> {
    let mut list = data::TpmlPcrSelection::new();
    let pcr_select_size = pcr_count.div_ceil(8);
    if pcr_select_size > data::TPM_PCR_SELECT_MAX {
        return Err(TpmError::PcrSelection(format!(
            "required pcr select size {pcr_select_size} exceeds maximum {}",
            data::TPM_PCR_SELECT_MAX
        )));
    }

    let pairs = PcrSelectionParser::parse(Rule::selection, selection_str)
        .map_err(|e| TpmError::PcrSelection(e.to_string()))?;

    for pair in pairs.flatten().filter(|p| p.as_rule() == Rule::bank) {
        let mut inner_pairs = pair.into_inner();

        let alg_str = inner_pairs.next().unwrap().as_str();
        let alg = PcrAlgId::from_str(alg_str)
            .map_err(|()| TpmError::PcrSelection(format!("invalid algorithm: {alg_str}")))?
            .0;

        let colon_and_list_pair = inner_pairs.next().unwrap();
        let pcr_list_pair = colon_and_list_pair.into_inner().next().unwrap();
        let mut pcr_select_bytes = vec![0u8; pcr_select_size];

        for pcr_index_pair in pcr_list_pair.into_inner() {
            let pcr_index: usize = pcr_index_pair.as_str().parse()?;

            if pcr_index >= pcr_count {
                return Err(TpmError::PcrSelection(format!(
                    "pcr index {pcr_index} is out of range for a TPM with {pcr_count} PCRs"
                )));
            }

            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }

        list.try_push(data::TpmsPcrSelection {
            hash: alg,
            pcr_select: tpm2_protocol::TpmBuffer::try_from(pcr_select_bytes.as_slice())?,
        })?;
    }

    Ok(list)
}

struct PcrAlgId(data::TpmAlgId);

impl FromStr for PcrAlgId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha1" => Ok(Self(data::TpmAlgId::Sha1)),
            "sha256" => Ok(Self(data::TpmAlgId::Sha256)),
            "sha384" => Ok(Self(data::TpmAlgId::Sha384)),
            "sha512" => Ok(Self(data::TpmAlgId::Sha512)),
            _ => Err(()),
        }
    }
}
