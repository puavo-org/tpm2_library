// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 11.1 `TPM2_StartAuthSession`
//! 11.2 `TPM2_PolicyRestart`

use crate::{
    data::{Tpm2b, Tpm2bNonce, TpmAlgId, TpmCc, TpmSe, TpmtSymDefObject},
    tpm_response, tpm_struct, TpmSession,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmStartAuthSessionCommand,
    TpmCc::StartAuthSession,
    true,
    true,
    2,
    {
        pub nonce_caller: Tpm2bNonce,
        pub encrypted_salt: Tpm2b,
        pub session_type: TpmSe,
        pub symmetric: TpmtSymDefObject,
        pub auth_hash: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmStartAuthSessionResponse,
    TpmCc::StartAuthSession,
    true,
    false,
    0,
    {
        pub session_handle: TpmSession,
        pub nonce_tpm: Tpm2bNonce,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyRestartCommand,
    TpmCc::PolicyRestart,
    false,
    true,
    1,
    {}
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyRestartResponse,
    TpmCc::PolicyRestart,
    false,
    true,
    {}
}
