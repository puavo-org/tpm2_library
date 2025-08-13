// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::PrintError, AuthSession, Command, TpmDevice, TpmError};

impl Command for PrintError {
    fn run(&self, _device: &mut TpmDevice, _session: Option<&AuthSession>) -> Result<(), TpmError> {
        println!("{}", self.rc);
        Ok(())
    }
}
