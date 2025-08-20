// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

use crate::{
    data::{Tpm2bData, TpmCc},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmVendorTcgTestCommand,
    cc: TpmCc::VendorTcgTest,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub input_data: Tpm2bData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmVendorTcgTestResponse,
    cc: TpmCc::VendorTcgTest,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub output_data: Tpm2bData,
    }
}
