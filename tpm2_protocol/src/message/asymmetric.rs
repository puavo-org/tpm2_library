// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 14 Asymmetric Primitives

use crate::{
    data::{
        Tpm2bData, Tpm2bEccPoint, Tpm2bMaxBuffer, Tpm2bPublicKeyRsa, TpmCc, TpmEccCurve,
        TpmiEccKeyExchange, TpmsAlgorithmDetailEcc, TpmtKdfScheme, TpmtRsaDecrypt,
    },
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmRsaEncryptCommand,
    cc: TpmCc::RsaEncrypt,
    no_sessions: true,
    with_sessions: true,
    handles: {
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub message: Tpm2bPublicKeyRsa,
        pub in_scheme: TpmtRsaDecrypt,
        pub label: Tpm2bData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmRsaEncryptResponse,
    cc: TpmCc::RsaEncrypt,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_data: Tpm2bPublicKeyRsa,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmRsaDecryptCommand,
    cc: TpmCc::RsaDecrypt,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub cipher_text: Tpm2bPublicKeyRsa,
        pub in_scheme: TpmtRsaDecrypt,
        pub label: Tpm2bData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmRsaDecryptResponse,
    cc: TpmCc::RsaDecrypt,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub message: Tpm2bPublicKeyRsa,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmEcdhKeyGenCommand,
    cc: TpmCc::EcdhKeyGen,
    no_sessions: true,
    with_sessions: true,
    handles: {
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEcdhKeyGenResponse,
    cc: TpmCc::EcdhKeyGen,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub z_point: Tpm2bEccPoint,
        pub pub_point: Tpm2bEccPoint,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmEcdhZGenCommand,
    cc: TpmCc::EcdhZGen,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub in_point: Tpm2bEccPoint,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEcdhZGenResponse,
    cc: TpmCc::EcdhZGen,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_point: Tpm2bEccPoint,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmEccParametersCommand,
    cc: TpmCc::EccParameters,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub curve_id: TpmEccCurve,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEccParametersResponse,
    cc: TpmCc::EccParameters,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub parameters: TpmsAlgorithmDetailEcc,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmZGen2PhaseCommand,
    cc: TpmCc::ZGen2Phase,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub key_a: crate::data::TpmiDhObject,
    },
    parameters: {
        pub in_qsb: Tpm2bEccPoint,
        pub in_qeb: Tpm2bEccPoint,
        pub in_scheme: TpmiEccKeyExchange,
        pub counter: u16,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmZGen2PhaseResponse,
    cc: TpmCc::ZGen2Phase,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_z1: Tpm2bEccPoint,
        pub out_z2: Tpm2bEccPoint,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmEccEncryptCommand,
    cc: TpmCc::EccEncrypt,
    no_sessions: true,
    with_sessions: true,
    handles: {
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub plaintext: Tpm2bMaxBuffer,
        pub in_scheme: TpmtKdfScheme,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEccEncryptResponse,
    cc: TpmCc::EccEncrypt,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub c1: Tpm2bEccPoint,
        pub c2: crate::data::Tpm2bMaxBuffer,
        pub c3: crate::data::Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmEccDecryptCommand,
    cc: TpmCc::EccDecrypt,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub c1: Tpm2bEccPoint,
        pub c2: crate::data::Tpm2bMaxBuffer,
        pub c3: crate::data::Tpm2bDigest,
        pub in_scheme: TpmtKdfScheme,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEccDecryptResponse,
    cc: TpmCc::EccDecrypt,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub plaintext: crate::data::Tpm2bMaxBuffer,
    }
}
