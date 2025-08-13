// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use tpm2_protocol::data::TpmRc;

pub fn run(rc: TpmRc) {
    println!("{rc}");
}
