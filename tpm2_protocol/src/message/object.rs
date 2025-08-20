// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Object Commands

use crate::{
    data::{
        Tpm2bAuth, Tpm2bCreationData, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bIdObject,
        Tpm2bName, Tpm2bPrivate, Tpm2bPublic, Tpm2bSensitive, Tpm2bSensitiveCreate,
        Tpm2bSensitiveData, TpmCc, TpmRh, TpmlPcrSelection, TpmtTkCreation,
    },
    tpm_struct, TpmTransient,
};
use core::fmt::Debug;

pub type Tpm2bTemplate = Tpm2bPublic;

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmCreateCommand,
    cc: TpmCc::Create,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub parent_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub in_sensitive: Tpm2bSensitiveCreate,
        pub in_public: Tpm2bPublic,
        pub outside_info: Tpm2bData,
        pub creation_pcr: TpmlPcrSelection,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmCreateResponse,
    cc: TpmCc::Create,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_private: Tpm2bPrivate,
        pub out_public: Tpm2bPublic,
        pub creation_data: Tpm2bCreationData,
        pub creation_hash: Tpm2bDigest,
        pub creation_ticket: TpmtTkCreation,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmCreateLoadedCommand,
    cc: TpmCc::CreateLoaded,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub parent_handle: crate::data::TpmiDhParent,
    },
    parameters: {
        pub in_sensitive: Tpm2bSensitiveCreate,
        pub in_public: Tpm2bTemplate,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmCreateLoadedResponse,
    cc: TpmCc::CreateLoaded,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub object_handle: TpmTransient,
    },
    parameters: {
        pub out_private: Tpm2bPrivate,
        pub out_public: Tpm2bPublic,
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmLoadCommand,
    cc: TpmCc::Load,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub parent_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub in_private: Tpm2bPrivate,
        pub in_public: Tpm2bPublic,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmLoadResponse,
    cc: TpmCc::Load,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub object_handle: TpmTransient,
    },
    parameters: {
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmLoadExternalCommand,
    cc: TpmCc::LoadExternal,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub in_private: Tpm2bSensitive,
        pub in_public: Tpm2bPublic,
        pub hierarchy: TpmRh,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmLoadExternalResponse,
    cc: TpmCc::LoadExternal,
    no_sessions: true,
    with_sessions: true,
    handles: {
        pub object_handle: TpmTransient,
    },
    parameters: {
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmReadPublicCommand,
    cc: TpmCc::ReadPublic,
    no_sessions: true,
    with_sessions: true,
    handles: {
        pub object_handle: crate::data::TpmiDhObject,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmReadPublicResponse,
    cc: TpmCc::ReadPublic,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub out_public: Tpm2bPublic,
        pub name: Tpm2bName,
        pub qualified_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmActivateCredentialCommand,
    cc: TpmCc::ActivateCredential,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub activate_handle: crate::data::TpmiDhObject,
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub credential_blob: Tpm2bIdObject,
        pub secret: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmActivateCredentialResponse,
    cc: TpmCc::ActivateCredential,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub cert_info: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmMakeCredentialCommand,
    cc: TpmCc::MakeCredential,
    no_sessions: true,
    with_sessions: true,
    handles: {
        pub handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub credential: Tpm2bDigest,
        pub object_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmMakeCredentialResponse,
    cc: TpmCc::MakeCredential,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub credential_blob: Tpm2bIdObject,
        pub secret: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmUnsealCommand,
    cc: TpmCc::Unseal,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub item_handle: crate::data::TpmiDhObject,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmUnsealResponse,
    cc: TpmCc::Unseal,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_data: Tpm2bSensitiveData,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmObjectChangeAuthCommand,
    cc: TpmCc::ObjectChangeAuth,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub object_handle: crate::data::TpmiDhObject,
        pub parent_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub new_auth: Tpm2bAuth,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmObjectChangeAuthResponse,
    cc: TpmCc::ObjectChangeAuth,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_private: Tpm2bPrivate,
    }
}
