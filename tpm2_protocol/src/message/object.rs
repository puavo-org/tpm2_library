// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    data::{
        Tpm2b, Tpm2bAuth, Tpm2bCreationData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bIdObject,
        Tpm2bName, Tpm2bPrivate, Tpm2bPublic, Tpm2bSensitive, Tpm2bSensitiveCreate, TpmCc, TpmRh,
        TpmlPcrSelection, TpmtTkCreation,
    },
    tpm_response, tpm_struct, TpmTransient,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmCreateCommand,
    TpmCc::Create,
    false,
    true,
    1,
    {
        pub in_sensitive: Tpm2bSensitiveCreate,
        pub in_public: Tpm2bPublic,
        pub outside_info: Tpm2b,
        pub creation_pcr: TpmlPcrSelection,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCreateResponse,
    TpmCc::Create,
    false,
    true,
    {
        pub out_private: Tpm2bPrivate,
        pub out_public: Tpm2bPublic,
        pub creation_data: Tpm2bCreationData,
        pub creation_hash: Tpm2bDigest,
        pub creation_ticket: TpmtTkCreation,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmLoadCommand,
    TpmCc::Load,
    false,
    true,
    1,
    {
        pub in_private: Tpm2bPrivate,
        pub in_public: Tpm2bPublic,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmLoadResponse,
    TpmCc::Load,
    false,
    true,
    pub object_handle: TpmTransient,
    {
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmLoadExternalCommand,
    TpmCc::LoadExternal,
    true,
    true,
    0,
    {
        pub in_private: Tpm2bSensitive,
        pub in_public: Tpm2bPublic,
        pub hierarchy: TpmRh,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmLoadExternalResponse,
    TpmCc::LoadExternal,
    true,
    true,
    pub object_handle: TpmTransient,
    {
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmReadPublicCommand,
    TpmCc::ReadPublic,
    true,
    true,
    1,
    {}
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmReadPublicResponse,
    TpmCc::ReadPublic,
    true,
    false,
    {
        pub out_public: Tpm2bPublic,
        pub name: Tpm2bName,
        pub qualified_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmActivateCredentialCommand,
    TpmCc::ActivateCredential,
    true,
    true,
    2,
    {
        pub credential_blob: Tpm2bIdObject,
        pub secret: Tpm2bEncryptedSecret,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmActivateCredentialResponse,
    TpmCc::ActivateCredential,
    true,
    true,
    {
        pub cert_info: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmMakeCredentialCommand,
    TpmCc::MakeCredential,
    true,
    true,
    1,
    {
        pub credential: Tpm2bDigest,
        pub object_name: Tpm2bName,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmMakeCredentialResponse,
    TpmCc::MakeCredential,
    true,
    true,
    {
        pub credential_blob: Tpm2bIdObject,
        pub secret: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmUnsealCommand,
    TpmCc::Unseal,
    false,
    true,
    1,
    {}
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmUnsealResponse,
    TpmCc::Unseal,
    false,
    true,
    {
        pub out_data: Tpm2b,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmObjectChangeAuthCommand,
    TpmCc::ObjectChangeAuth,
    false,
    true,
    2,
    {
        pub new_auth: Tpm2bAuth,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmObjectChangeAuthResponse,
    TpmCc::ObjectChangeAuth,
    false,
    true,
    {
        pub out_private: Tpm2bPrivate,
    }
}
