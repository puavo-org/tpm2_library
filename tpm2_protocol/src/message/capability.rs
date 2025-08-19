// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 30.2 `TPM2_GetCapability`
//! 30.3 `TPM2_TestParms`
//! 30.4 `TPM2_SetCapability` (TODO)

use crate::{
    data::{TpmCap, TpmCc, TpmiYesNo, TpmsCapabilityData, TpmtPublicParms},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmTestParmsCommand,
    TpmCc::TestParms,
    true,
    false,
    0,
    {
        pub parameters: TpmtPublicParms,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmTestParmsResponse,
    TpmCc::TestParms,
    true,
    false,
    0,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetCapabilityCommand,
    TpmCc::GetCapability,
    true,
    true,
    0,
    {
        pub cap: TpmCap,
        pub property: u32,
        pub property_count: u32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetCapabilityResponse,
    TpmCc::GetCapability,
    true,
    false,
    0,
    {
        pub more_data: TpmiYesNo,
        pub capability_data: TpmsCapabilityData,
    }
}
