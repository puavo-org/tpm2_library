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
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

pub type TpmiAlgCipherMode = TpmAlgId;
pub type TpmiAlgMacScheme = TpmAlgId;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEncryptDecryptCommand,
    TpmCc::EncryptDecrypt,
    false,
    true,
    1,
    {
        pub decrypt: TpmiYesNo,
        pub mode: TpmiAlgCipherMode,
        pub iv_in: Tpm2bIv,
        pub in_data: Tpm2bMaxBuffer,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEncryptDecryptResponse,
    TpmCc::EncryptDecrypt,
    false,
    true,
    {
        pub out_data: Tpm2bMaxBuffer,
        pub iv_out: Tpm2bIv,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEncryptDecrypt2Command,
    TpmCc::EncryptDecrypt2,
    false,
    true,
    1,
    {
        pub in_data: Tpm2bMaxBuffer,
        pub decrypt: TpmiYesNo,
        pub mode: TpmAlgId,
        pub iv_in: Tpm2bIv,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEncryptDecrypt2Response,
    TpmCc::EncryptDecrypt2,
    false,
    true,
    {
        pub out_data: Tpm2bMaxBuffer,
        pub iv_out: Tpm2bIv,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHashCommand,
    TpmCc::Hash,
    true,
    false,
    0,
    {
        pub data: Tpm2bMaxBuffer,
        pub hash_alg: TpmAlgId,
        pub hierarchy: TpmRh,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHashResponse,
    TpmCc::Hash,
    true,
    false,
    {
        pub out_hash: Tpm2bDigest,
        pub validation: TpmtTkHashcheck,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHmacCommand,
    TpmCc::Hmac,
    false,
    true,
    1,
    {
        pub buffer: Tpm2bMaxBuffer,
        pub hash_alg: TpmiAlgHash,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHmacResponse,
    TpmCc::Hmac,
    false,
    true,
    {
        pub out_hmac: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmMacCommand,
    TpmCc::Hmac,
    false,
    true,
    1,
    {
        pub buffer: Tpm2bMaxBuffer,
        pub in_scheme: TpmiAlgMacScheme,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmMacResponse,
    TpmCc::Hmac,
    false,
    true,
    {
        pub out_mac: Tpm2bDigest,
    }
}
