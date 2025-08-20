// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 32 Attached Components

use crate::{
    data::{Tpm2bMaxBuffer, Tpm2bName, TpmAt, TpmCc, TpmiYesNo, TpmlAcCapabilities, TpmsAcOutput},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmAcGetCapabilityCommand,
    cc: TpmCc::AcGetCapability,
    no_sessions: true,
    with_sessions: false,
    handles: {
        pub ac: u32,
    },
    parameters: {
        pub capability: TpmAt,
        pub count: u32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmAcGetCapabilityResponse,
    cc: TpmCc::AcGetCapability,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub more_data: TpmiYesNo,
        pub capabilities_data: TpmlAcCapabilities,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmAcSendCommand,
    cc: TpmCc::AcSend,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub send_object: crate::data::TpmiDhObject,
        pub auth_handle: crate::data::TpmiDhObject,
        pub ac: u32,
    },
    parameters: {
        pub ac_data_in: Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmAcSendResponse,
    cc: TpmCc::AcSend,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub ac_data_out: TpmsAcOutput,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyAcSendSelectCommand,
    cc: TpmCc::PolicyAcSendSelect,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub object_name: Tpm2bName,
        pub auth_handle_name: Tpm2bName,
        pub ac_name: Tpm2bName,
        pub include_object: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmPolicyAcSendSelectResponse,
    cc: TpmCc::PolicyAcSendSelect,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmActSetTimeoutCommand,
    cc: TpmCc::ActSetTimeout,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub act_handle: u32,
    },
    parameters: {
        pub start_timeout: u32,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmActSetTimeoutResponse,
    cc: TpmCc::ActSetTimeout,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}
