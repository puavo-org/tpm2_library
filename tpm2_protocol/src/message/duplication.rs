// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 13.1 `TPM2_Duplicate`
//! 13.2 `TPM2_Rewrap`
//! 13.3 `TPM2_Import`

use crate::{
    data::{
        Tpm2bData, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmCc, TpmtSymDef,
        TpmtSymDefObject,
    },
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmDuplicateCommand,
    TpmCc::Duplicate,
    false,
    true,
    2,
    {
        pub encryption_key_in: Tpm2bData,
        pub symmetric_alg: TpmtSymDefObject,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmDuplicateResponse,
    TpmCc::Duplicate,
    false,
    true,
    {
        pub encryption_key_out: Tpm2bData,
        pub duplicate: Tpm2bPrivate,
        pub out_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRewrapCommand,
    TpmCc::Rewrap,
    false,
    true,
    2,
    {
        pub in_duplicate: Tpm2bPrivate,
        pub name: Tpm2bName,
        pub in_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRewrapResponse,
    TpmCc::Rewrap,
    false,
    true,
    {
        pub out_duplicate: Tpm2bPrivate,
        pub out_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmImportCommand,
    TpmCc::Import,
    false,
    true,
    1,
    {
        pub encryption_key: Tpm2bData,
        pub object_public: Tpm2bPublic,
        pub duplicate: Tpm2bPrivate,
        pub in_sym_seed: Tpm2bEncryptedSecret,
        pub symmetric_alg: TpmtSymDef,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmImportResponse,
    TpmCc::Import,
    false,
    true,
    {
        pub out_private: Tpm2bPrivate,
    }
}
