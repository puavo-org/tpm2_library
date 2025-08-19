// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

use crate::{
    data::{TpmAlgId, TpmSt},
    tpm_bool, tpm_enum, tpm_handle, TpmNotDiscriminant,
};

tpm_bool! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct TpmiYesNo(bool);
}

tpm_enum! {
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Default)]
    pub enum TpmiEccKeyExchange(u16) {
        #[default]
        (None, 0x0000, "TPM_ECC_NONE"),
        (Ecdh, 0x0019, "TPM_ALG_ECDH"),
        (Ecmqv, 0x001D, "TPM_ALG_ECMQV"),
        (Sm2, 0x001B, "TPM_ALG_SM2"),
    }
}

pub type TpmiAlgHash = TpmAlgId;
pub type TpmiAlgSymObject = TpmAlgId;
pub type TpmiStCommandTag = TpmSt;

tpm_handle! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    TpmiDhObject
}

tpm_handle! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    TpmiDhParent
}

tpm_handle! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    TpmiShAuthSession
}

tpm_handle! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    TpmiRhHierarchy
}
