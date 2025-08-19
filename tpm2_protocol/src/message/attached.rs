// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 32 Attached Components

use crate::{
    data::{Tpm2bMaxBuffer, Tpm2bName, TpmAt, TpmCc, TpmiYesNo, TpmlAcCapabilities, TpmsAcOutput},
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmAcGetCapabilityCommand,
    TpmCc::AcGetCapability,
    true,
    false,
    1,
    {
        pub capability: TpmAt,
        pub count: u32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmAcGetCapabilityResponse,
    TpmCc::AcGetCapability,
    true,
    false,
    0,
    {
        pub more_data: TpmiYesNo,
        pub capabilities_data: TpmlAcCapabilities,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmAcSendCommand,
    TpmCc::AcSend,
    false,
    true,
    3,
    {
        pub ac_data_in: Tpm2bMaxBuffer,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmAcSendResponse,
    TpmCc::AcSend,
    false,
    true,
    {
        pub ac_data_out: TpmsAcOutput,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyAcSendSelectCommand,
    TpmCc::PolicyAcSendSelect,
    false,
    true,
    1,
    {
        pub object_name: Tpm2bName,
        pub auth_handle_name: Tpm2bName,
        pub ac_name: Tpm2bName,
        pub include_object: TpmiYesNo,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyAcSendSelectResponse,
    TpmCc::PolicyAcSendSelect,
    false,
    true,
    {
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmActSetTimeoutCommand,
    TpmCc::ActSetTimeout,
    false,
    true,
    1,
    {
        pub start_timeout: u32,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmActSetTimeoutResponse,
    TpmCc::ActSetTimeout,
    false,
    true,
    {
    }
}
