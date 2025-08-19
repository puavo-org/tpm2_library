// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

use crate::{
    data::{Tpm2bData, TpmCc},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmVendorTcgTestCommand,
    TpmCc::VendorTcgTest,
    true,
    false,
    0,
    {
        pub input_data: Tpm2bData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmVendorTcgTestResponse,
    TpmCc::VendorTcgTest,
    true,
    false,
    0,
    {
        pub output_data: Tpm2bData,
    }
}
