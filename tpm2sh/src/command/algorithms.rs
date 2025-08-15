// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli, cli::Algorithms, enumerate_all, AuthSession, Command, TpmDevice, TpmError,
    TPM_CAP_PROPERTY_MAX,
};
use regex::Regex;
use std::collections::HashSet;
use tpm2_protocol::data::{TpmAlgId, TpmCap, TpmuCapabilities};

fn get_chip_algorithms(
    device: &mut TpmDevice,
    log_format: cli::LogFormat,
) -> Result<HashSet<TpmAlgId>, TpmError> {
    let cap_data_vec = device.get_capability(TpmCap::Algs, 0, TPM_CAP_PROPERTY_MAX, log_format)?;
    let algs: HashSet<TpmAlgId> = cap_data_vec
        .into_iter()
        .flat_map(|cap_data| {
            if let TpmuCapabilities::Algs(p) = cap_data.data {
                p.iter().map(|prop| prop.alg).collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        })
        .collect();
    Ok(algs)
}

impl Command for Algorithms {
    /// Runs `algorithms`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(
        &self,
        device: &mut TpmDevice,
        _session: Option<&AuthSession>,
        log_format: cli::LogFormat,
    ) -> Result<(), TpmError> {
        let chip_algorithms = get_chip_algorithms(device, log_format)?;
        let cli_algorithms = enumerate_all();

        let supported_algorithms: Vec<_> = cli_algorithms
            .into_iter()
            .filter(|alg| chip_algorithms.contains(&alg.object_type))
            .collect();

        let filtered_algorithms: Vec<_> = if let Some(pattern) = &self.filter {
            let re = Regex::new(pattern)
                .map_err(|e| TpmError::Execution(format!("invalid regex: {e}")))?;
            supported_algorithms
                .into_iter()
                .filter(|alg| re.is_match(&alg.name))
                .collect()
        } else {
            supported_algorithms
        };

        let mut sorted_names: Vec<_> = filtered_algorithms
            .into_iter()
            .map(|alg| alg.name)
            .collect();
        sorted_names.sort();
        for name in sorted_names {
            println!("{name}");
        }
        Ok(())
    }
}
