// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 20.1 `TPM2_VerifySignature`
//! 20.2 `TPM2_Sign`

use crate::{
    data::{Tpm2bDigest, TpmCc, TpmtSignature, TpmtTkHashcheck, TpmtTkVerified},
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSignCommand,
    TpmCc::Sign,
    false,
    true,
    1,
    {
        pub digest: Tpm2bDigest,
        pub in_scheme: TpmtSignature,
        pub validation: TpmtTkHashcheck,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSignResponse,
    TpmCc::Sign,
    false,
    true,
    {
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmVerifySignatureCommand,
    TpmCc::VerifySignature,
    true,
    false,
    1,
    {
        pub digest: Tpm2bDigest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmVerifySignatureResponse,
    TpmCc::VerifySignature,
    true,
    false,
    0,
    {
        pub validation: TpmtTkVerified,
    }
}
