// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 25.2 `TPM2_DictionaryAttackLockReset`
//! 25.3 `TPM2_DictionaryAttackParameters`

use crate::{data::TpmCc, tpm_response, tpm_struct};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmDictionaryAttackLockResetCommand,
    TpmCc::DictionaryAttackLockReset,
    false,
    true,
    1,
    {}
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmDictionaryAttackLockResetResponse,
    TpmCc::DictionaryAttackLockReset,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmDictionaryAttackParametersCommand,
    TpmCc::DictionaryAttackParameters,
    false,
    true,
    1,
    {
        pub new_max_tries: u32,
        pub new_recovery_time: u32,
        pub lockout_recovery: u32,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmDictionaryAttackParametersResponse,
    TpmCc::DictionaryAttackParameters,
    false,
    true,
    {}
}
