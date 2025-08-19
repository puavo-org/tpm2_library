// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 16.1 `TPM2_GetRandom`
//! 16.2 `TPM2_StirRandom`

use crate::{
    data::{Tpm2bDigest, Tpm2bSensitiveData, TpmCc},
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmGetRandomCommand,
    TpmCc::GetRandom,
    true,
    true,
    0,
    {
        pub bytes_requested: u16,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmGetRandomResponse,
    TpmCc::GetRandom,
    true,
    true,
    {
        pub random_bytes: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmStirRandomCommand,
    TpmCc::StirRandom,
    true,
    true,
    0,
    {
        pub in_data: Tpm2bSensitiveData,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmStirRandomResponse,
    TpmCc::StirRandom,
    true,
    true,
    {}
}
