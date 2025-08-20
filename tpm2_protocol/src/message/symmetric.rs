// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 15.2 `TPM2_EncryptDecrypt`
//! 15.3 `TPM2_EncryptDecrypt2`
//! 15.4 `TPM2_Hash`
//! 15.5 `TPM2_HMAC`
//! 15.6 `TPM2_MAC`

use crate::{
    data::{
        Tpm2bDigest, Tpm2bIv, Tpm2bMaxBuffer, TpmAlgId, TpmCc, TpmRh, TpmiAlgHash, TpmiYesNo,
        TpmtTkHashcheck,
    },
    tpm_struct,
};
use core::fmt::Debug;

pub type TpmiAlgCipherMode = TpmAlgId;
pub type TpmiAlgMacScheme = TpmAlgId;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmEncryptDecryptCommand,
    cc: TpmCc::EncryptDecrypt,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub decrypt: TpmiYesNo,
        pub mode: TpmiAlgCipherMode,
        pub iv_in: Tpm2bIv,
        pub in_data: Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEncryptDecryptResponse,
    cc: TpmCc::EncryptDecrypt,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_data: Tpm2bMaxBuffer,
        pub iv_out: Tpm2bIv,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmEncryptDecrypt2Command,
    cc: TpmCc::EncryptDecrypt2,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub in_data: Tpm2bMaxBuffer,
        pub decrypt: TpmiYesNo,
        pub mode: TpmAlgId,
        pub iv_in: Tpm2bIv,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEncryptDecrypt2Response,
    cc: TpmCc::EncryptDecrypt2,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_data: Tpm2bMaxBuffer,
        pub iv_out: Tpm2bIv,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmHashCommand,
    cc: TpmCc::Hash,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub data: Tpm2bMaxBuffer,
        pub hash_alg: TpmAlgId,
        pub hierarchy: TpmRh,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmHashResponse,
    cc: TpmCc::Hash,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub out_hash: Tpm2bDigest,
        pub validation: TpmtTkHashcheck,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmHmacCommand,
    cc: TpmCc::Hmac,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub buffer: Tpm2bMaxBuffer,
        pub hash_alg: TpmiAlgHash,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmHmacResponse,
    cc: TpmCc::Hmac,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_hmac: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmMacCommand,
    cc: TpmCc::Hmac,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub buffer: Tpm2bMaxBuffer,
        pub in_scheme: TpmiAlgMacScheme,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmMacResponse,
    cc: TpmCc::Hmac,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_mac: Tpm2bDigest,
    }
}
