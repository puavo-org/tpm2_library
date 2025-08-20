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
    kind: Command,
    name: TpmTestParmsCommand,
    cc: TpmCc::TestParms,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub parameters: TpmtPublicParms,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmTestParmsResponse,
    cc: TpmCc::TestParms,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmGetCapabilityCommand,
    cc: TpmCc::GetCapability,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub cap: TpmCap,
        pub property: u32,
        pub property_count: u32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetCapabilityResponse,
    cc: TpmCc::GetCapability,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub more_data: TpmiYesNo,
        pub capability_data: TpmsCapabilityData,
    }
}
