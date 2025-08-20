// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 25.2 `TPM2_DictionaryAttackLockReset`
//! 25.3 `TPM2_DictionaryAttackParameters`

use crate::{data::TpmCc, tpm_struct};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmDictionaryAttackLockResetCommand,
    cc: TpmCc::DictionaryAttackLockReset,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub lock_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmDictionaryAttackLockResetResponse,
    cc: TpmCc::DictionaryAttackLockReset,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmDictionaryAttackParametersCommand,
    cc: TpmCc::DictionaryAttackParameters,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub lock_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub new_max_tries: u32,
        pub new_recovery_time: u32,
        pub lockout_recovery: u32,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmDictionaryAttackParametersResponse,
    cc: TpmCc::DictionaryAttackParameters,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}
