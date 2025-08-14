// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{cli, cli::Objects, AuthSession, Command, TpmDevice, TpmError};
use tpm2_protocol::{data::TpmRh, TpmPersistent, TpmTransient};

impl Command for Objects {
    /// Runs `objects`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, device: &mut TpmDevice, _session: Option<&AuthSession>) -> Result<(), TpmError> {
        let transient_handles = cli::get_handles(device, TpmRh::TransientFirst)?;
        for handle in transient_handles {
            let obj = cli::Object::Handle(TpmTransient(handle));
            let json_line = serde_json::to_string(&obj)?;
            println!("{json_line}");
        }

        let persistent_handles = cli::get_handles(device, TpmRh::PersistentFirst)?;
        for handle in persistent_handles {
            let obj = cli::Object::Persistent(TpmPersistent(handle));
            let json_line = serde_json::to_string(&obj)?;
            println!("{json_line}");
        }

        Ok(())
    }
}
