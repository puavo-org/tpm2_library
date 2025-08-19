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
    tpm_response, tpm_struct, TpmTransient,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmCreatePrimaryCommand,
    TpmCc::CreatePrimary,
    false,
    true,
    1,
    {
        pub in_sensitive: Tpm2bSensitiveCreate,
        pub in_public: Tpm2bPublic,
        pub outside_info: Tpm2bData,
        pub creation_pcr: TpmlPcrSelection,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCreatePrimaryResponse,
    TpmCc::CreatePrimary,
    false,
    true,
    pub object_handle: TpmTransient,
    {
        pub out_public: Tpm2bPublic,
        pub creation_data: Tpm2bCreationData,
        pub creation_hash: Tpm2bDigest,
        pub creation_ticket: TpmtTkCreation,
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHierarchyControlCommand,
    TpmCc::HierarchyControl,
    false,
    true,
    1,
    {
        pub enable: TpmRh,
        pub state: TpmiYesNo,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmHierarchyControlResponse,
    TpmCc::HierarchyControl,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHierarchyChangeAuthCommand,
    TpmCc::HierarchyChangeAuth,
    false,
    true,
    1,
    {
        pub new_auth: Tpm2bAuth,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmHierarchyChangeAuthResponse,
    TpmCc::HierarchyChangeAuth,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangePpsCommand,
    TpmCc::ChangePps,
    false,
    true,
    1,
    {}
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangePpsResponse,
    TpmCc::ChangePps,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangeEpsCommand,
    TpmCc::ChangeEps,
    false,
    true,
    1,
    {}
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangeEpsResponse,
    TpmCc::ChangeEps,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClearCommand,
    TpmCc::Clear,
    false,
    true,
    1,
    {}
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClearResponse,
    TpmCc::Clear,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmClearControlCommand,
    TpmCc::ClearControl,
    false,
    true,
    1,
    {
        pub disable: TpmiYesNo,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClearControlResponse,
    TpmCc::ClearControl,
    false,
    true,
    {}
}

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSetPrimaryPolicyCommand,
    TpmCc::SetPrimaryPolicy,
    false,
    true,
    1,
    {
        pub auth_policy: Tpm2bDigest,
        pub hash_alg: TpmAlgId,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmSetPrimaryPolicyResponse,
    TpmCc::SetPrimaryPolicy,
    false,
    true,
    {}
);

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmReadOnlyControlCommand,
    TpmCc::ReadOnlyControl,
    false,
    true,
    1,
    {
        pub state: TpmiYesNo,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmReadOnlyControlResponse,
    TpmCc::ReadOnlyControl,
    false,
    true,
    {}
}
