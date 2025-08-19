// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 19.2 `TPM2_Commit`
//! 19.3 `TPM2_EC_Ephemeral`

use crate::{
    data::{Tpm2bEccParameter, Tpm2bEccPoint, Tpm2bSensitiveData, TpmCc, TpmEccCurve},
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmCommitCommand,
    TpmCc::Commit,
    false,
    true,
    1,
    {
        pub p1: Tpm2bEccPoint,
        pub s2: Tpm2bSensitiveData,
        pub y2: Tpm2bEccParameter,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmCommitResponse,
    TpmCc::Commit,
    false,
    true,
    {
        pub k: Tpm2bEccPoint,
        pub l: Tpm2bEccPoint,
        pub e: Tpm2bEccPoint,
        pub counter: u16,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmEcEphemeralCommand,
    TpmCc::EcEphemeral,
    true,
    false,
    0,
    {
        pub curve_id: TpmEccCurve,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmEcEphemeralResponse,
    TpmCc::EcEphemeral,
    true,
    false,
    0,
    {
        pub q: Tpm2bEccPoint,
        pub counter: u16,
    }
}
