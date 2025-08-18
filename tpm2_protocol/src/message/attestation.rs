// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 18 Attestation Commands

use crate::{
    data::{Tpm2bAttest, Tpm2bData, Tpm2bDigest, TpmCc, TpmtSignature, TpmtTkCreation},
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCertifyCommand,
    TpmCc::Certify,
    false,
    true,
    2,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}
tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCertifyResponse,
    TpmCc::Certify,
    false,
    true,
    {
        pub certify_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCertifyCreationCommand,
    TpmCc::CertifyCreation,
    false,
    true,
    2,
    {
        pub qualifying_data: Tpm2bData,
        pub creation_hash: Tpm2bDigest,
        pub in_scheme: TpmtSignature,
        pub creation_ticket: TpmtTkCreation,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCertifyCreationResponse,
    TpmCc::CertifyCreation,
    false,
    true,
    {
        pub certify_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetSessionAuditDigestCommand,
    TpmCc::GetSessionAuditDigest,
    false,
    true,
    3,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetSessionAuditDigestResponse,
    TpmCc::GetSessionAuditDigest,
    false,
    true,
    {
        pub audit_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetCommandAuditDigestCommand,
    TpmCc::GetCommandAuditDigest,
    false,
    true,
    2,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetCommandAuditDigestResponse,
    TpmCc::GetCommandAuditDigest,
    false,
    true,
    {
        pub audit_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetTimeCommand,
    TpmCc::GetTime,
    false,
    true,
    2,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetTimeResponse,
    TpmCc::GetTime,
    false,
    true,
    {
        pub time_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}
