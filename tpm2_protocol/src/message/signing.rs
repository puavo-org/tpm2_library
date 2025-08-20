// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 20.1 `TPM2_VerifySignature`
//! 20.2 `TPM2_Sign`

use crate::{
    data::{Tpm2bDigest, TpmCc, TpmtSignature, TpmtTkHashcheck, TpmtTkVerified},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmSignCommand,
    cc: TpmCc::Sign,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub digest: Tpm2bDigest,
        pub in_scheme: TpmtSignature,
        pub validation: TpmtTkHashcheck,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmSignResponse,
    cc: TpmCc::Sign,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmVerifySignatureCommand,
    cc: TpmCc::VerifySignature,
    no_sessions: true,
    with_sessions: false,
    handles: {
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub digest: Tpm2bDigest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmVerifySignatureResponse,
    cc: TpmCc::VerifySignature,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub validation: TpmtTkVerified,
    }
}
