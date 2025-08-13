// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{cli, cli::Objects, AuthSession, Command, TpmDevice, TpmError};
use tpm2_protocol::data::TpmRh;

impl Command for Objects {
    /// Runs `objects`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, device: &mut TpmDevice, _session: Option<&AuthSession>) -> Result<(), TpmError> {
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
}
