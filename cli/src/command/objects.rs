// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{cli, TpmDevice, TpmError};
use tpm2_protocol::data::TpmRh;

/// Executes the `objects` command.
///
/// # Errors
///
/// Returns a `TpmError` if communication with the TPM fails.
pub fn run(device: &mut TpmDevice) -> Result<(), TpmError> {
    let transient_handles = cli::get_handles(device, TpmRh::TransientFirst)?;
    for handle in transient_handles {
        println!("transient:{handle:#010x}");
    }

    let persistent_handles = cli::get_handles(device, TpmRh::PersistentFirst)?;
    for handle in persistent_handles {
        println!("persistent:{handle:#010x}");
    }

    Ok(())
}
