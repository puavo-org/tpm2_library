// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 19.2 `TPM2_Commit`
//! 19.3 `TPM2_EC_Ephemeral`

use crate::{
    data::{Tpm2bEccParameter, Tpm2bEccPoint, Tpm2bSensitiveData, TpmCc, TpmEccCurve},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmCommitCommand,
    cc: TpmCc::Commit,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub sign_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub p1: Tpm2bEccPoint,
        pub s2: Tpm2bSensitiveData,
        pub y2: Tpm2bEccParameter,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmCommitResponse,
    cc: TpmCc::Commit,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub k: Tpm2bEccPoint,
        pub l: Tpm2bEccPoint,
        pub e: Tpm2bEccPoint,
        pub counter: u16,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmEcEphemeralCommand,
    cc: TpmCc::EcEphemeral,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub curve_id: TpmEccCurve,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmEcEphemeralResponse,
    cc: TpmCc::EcEphemeral,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub q: Tpm2bEccPoint,
        pub counter: u16,
    }
}
