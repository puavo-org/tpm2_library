// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 11.1 `TPM2_StartAuthSession`
//! 11.2 `TPM2_PolicyRestart`

use crate::{
    data::{Tpm2b, Tpm2bNonce, TpmAlgId, TpmCc, TpmSe, TpmtSymDefObject},
    tpm_struct, TpmSession,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmStartAuthSessionCommand,
    cc: TpmCc::StartAuthSession,
    no_sessions: true,
    with_sessions: true,
    handles: {
        pub tpm_key: crate::data::TpmiDhObject,
        pub bind: crate::data::TpmiDhObject,
    },
    parameters: {
        pub nonce_caller: Tpm2bNonce,
        pub encrypted_salt: Tpm2b,
        pub session_type: TpmSe,
        pub symmetric: TpmtSymDefObject,
        pub auth_hash: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmStartAuthSessionResponse,
    cc: TpmCc::StartAuthSession,
    no_sessions: true,
    with_sessions: true,
    handles: {
        pub session_handle: TpmSession,
    },
    parameters: {
        pub nonce_tpm: Tpm2bNonce,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyRestartCommand,
    cc: TpmCc::PolicyRestart,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub session_handle: crate::data::TpmiShAuthSession,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyRestartResponse,
    cc: TpmCc::PolicyRestart,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}
