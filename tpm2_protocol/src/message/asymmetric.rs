// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 14 Asymmetric Primitives

use crate::{
    data::{
        Tpm2bData, Tpm2bEccPoint, Tpm2bMaxBuffer, Tpm2bPublicKeyRsa, TpmCc, TpmEccCurve,
        TpmiEccKeyExchange, TpmsAlgorithmDetailEcc, TpmtKdfScheme, TpmtRsaDecrypt,
    },
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRsaEncryptCommand,
    TpmCc::RsaEncrypt,
    true,
    true,
    1,
    {
        pub message: Tpm2bPublicKeyRsa,
        pub in_scheme: TpmtRsaDecrypt,
        pub label: Tpm2bData,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRsaEncryptResponse,
    TpmCc::RsaEncrypt,
    true,
    true,
    {
        pub out_data: Tpm2bPublicKeyRsa,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRsaDecryptCommand,
    TpmCc::RsaDecrypt,
    false,
    true,
    1,
    {
        pub cipher_text: Tpm2bPublicKeyRsa,
        pub in_scheme: TpmtRsaDecrypt,
        pub label: Tpm2bData,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRsaDecryptResponse,
    TpmCc::RsaDecrypt,
    false,
    true,
    {
        pub message: Tpm2bPublicKeyRsa,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmEcdhKeyGenCommand,
    TpmCc::EcdhKeyGen,
    true,
    true,
    1,
    {}
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEcdhKeyGenResponse,
    TpmCc::EcdhKeyGen,
    true,
    true,
    {
        pub z_point: Tpm2bEccPoint,
        pub pub_point: Tpm2bEccPoint,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmEcdhZGenCommand,
    TpmCc::EcdhZGen,
    false,
    true,
    1,
    {
        pub in_point: Tpm2bEccPoint,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEcdhZGenResponse,
    TpmCc::EcdhZGen,
    false,
    true,
    {
        pub out_point: Tpm2bEccPoint,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmEccParametersCommand,
    TpmCc::EccParameters,
    true,
    true,
    0,
    {
        pub curve_id: TpmEccCurve,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEccParametersResponse,
    TpmCc::EccParameters,
    true,
    true,
    {
        pub parameters: TpmsAlgorithmDetailEcc,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmZGen2PhaseCommand,
    TpmCc::ZGen2Phase,
    false,
    true,
    1,
    {
        pub in_qsb: Tpm2bEccPoint,
        pub in_qeb: Tpm2bEccPoint,
        pub in_scheme: TpmiEccKeyExchange,
        pub counter: u16,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmZGen2PhaseResponse,
    TpmCc::ZGen2Phase,
    false,
    true,
    {
        pub out_z1: Tpm2bEccPoint,
        pub out_z2: Tpm2bEccPoint,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEccEncryptCommand,
    TpmCc::EccEncrypt,
    true,
    true,
    1,
    {
        pub plaintext: Tpm2bMaxBuffer,
        pub in_scheme: TpmtKdfScheme,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEccEncryptResponse,
    TpmCc::EccEncrypt,
    true,
    true,
    {
        pub c1: Tpm2bEccPoint,
        pub c2: crate::data::Tpm2bMaxBuffer,
        pub c3: crate::data::Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEccDecryptCommand,
    TpmCc::EccDecrypt,
    false,
    true,
    1,
    {
        pub c1: Tpm2bEccPoint,
        pub c2: crate::data::Tpm2bMaxBuffer,
        pub c3: crate::data::Tpm2bDigest,
        pub in_scheme: TpmtKdfScheme,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEccDecryptResponse,
    TpmCc::EccDecrypt,
    false,
    true,
    {
        pub plaintext: crate::data::Tpm2bMaxBuffer,
    }
}
