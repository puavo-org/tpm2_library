// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 24.1 `TPM2_CreatePrimary`
//! 24.2 `TPM2_HierarchyControl`
//! 24.3 `TPM2_SetPrimaryPolicy`
//! 24.4 `TPM2_ChangePPS`
//! 24.5 `TPM2_ChangeEPS`
//! 24.6 `TPM2_Clear`
//! 24.7 `TPM2_ClearControl`
//! 24.8 `TPM2_HierarchyChangeAuth`
//! 24.9 `TPM2_ReadOnlyControl`

use crate::{
    data::{
        Tpm2bAuth, Tpm2bCreationData, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bPublic,
        Tpm2bSensitiveCreate, TpmAlgId, TpmCc, TpmRh, TpmiYesNo, TpmlPcrSelection, TpmtTkCreation,
    },
    tpm_struct, TpmTransient,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmCreatePrimaryCommand,
    cc: TpmCc::CreatePrimary,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub primary_handle: crate::data::TpmiRhHierarchy,
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
    name: TpmCreatePrimaryResponse,
    cc: TpmCc::CreatePrimary,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub object_handle: TpmTransient,
    },
    parameters: {
        pub out_public: Tpm2bPublic,
        pub creation_data: Tpm2bCreationData,
        pub creation_hash: Tpm2bDigest,
        pub creation_ticket: TpmtTkCreation,
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmHierarchyControlCommand,
    cc: TpmCc::HierarchyControl,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub enable: TpmRh,
        pub state: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmHierarchyControlResponse,
    cc: TpmCc::HierarchyControl,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmHierarchyChangeAuthCommand,
    cc: TpmCc::HierarchyChangeAuth,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub new_auth: Tpm2bAuth,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmHierarchyChangeAuthResponse,
    cc: TpmCc::HierarchyChangeAuth,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmChangePpsCommand,
    cc: TpmCc::ChangePps,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmChangePpsResponse,
    cc: TpmCc::ChangePps,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmChangeEpsCommand,
    cc: TpmCc::ChangeEps,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmChangeEpsResponse,
    cc: TpmCc::ChangeEps,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmClearCommand,
    cc: TpmCc::Clear,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmClearResponse,
    cc: TpmCc::Clear,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmClearControlCommand,
    cc: TpmCc::ClearControl,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub disable: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmClearControlResponse,
    cc: TpmCc::ClearControl,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmSetPrimaryPolicyCommand,
    cc: TpmCc::SetPrimaryPolicy,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub auth_policy: Tpm2bDigest,
        pub hash_alg: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmSetPrimaryPolicyResponse,
    cc: TpmCc::SetPrimaryPolicy,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmReadOnlyControlCommand,
    cc: TpmCc::ReadOnlyControl,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub state: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmReadOnlyControlResponse,
    cc: TpmCc::ReadOnlyControl,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}
