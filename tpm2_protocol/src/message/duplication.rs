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
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmDuplicateCommand,
    cc: TpmCc::Duplicate,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub object_handle: crate::data::TpmiDhObject,
        pub new_parent_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub encryption_key_in: Tpm2bData,
        pub symmetric_alg: TpmtSymDefObject,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmDuplicateResponse,
    cc: TpmCc::Duplicate,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub encryption_key_out: Tpm2bData,
        pub duplicate: Tpm2bPrivate,
        pub out_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmRewrapCommand,
    cc: TpmCc::Rewrap,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub old_parent: crate::data::TpmiDhObject,
        pub new_parent: crate::data::TpmiDhObject,
    },
    parameters: {
        pub in_duplicate: Tpm2bPrivate,
        pub name: Tpm2bName,
        pub in_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmRewrapResponse,
    cc: TpmCc::Rewrap,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_duplicate: Tpm2bPrivate,
        pub out_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmImportCommand,
    cc: TpmCc::Import,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub parent_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub encryption_key: Tpm2bData,
        pub object_public: Tpm2bPublic,
        pub duplicate: Tpm2bPrivate,
        pub in_sym_seed: Tpm2bEncryptedSecret,
        pub symmetric_alg: TpmtSymDef,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmImportResponse,
    cc: TpmCc::Import,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_private: Tpm2bPrivate,
    }
}
