// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 16.1 `TPM2_GetRandom`
//! 16.2 `TPM2_StirRandom`

use crate::{
    data::{Tpm2bDigest, Tpm2bSensitiveData, TpmCc},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmGetRandomCommand,
    cc: TpmCc::GetRandom,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub bytes_requested: u16,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetRandomResponse,
    cc: TpmCc::GetRandom,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub random_bytes: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmStirRandomCommand,
    cc: TpmCc::StirRandom,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub in_data: Tpm2bSensitiveData,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmStirRandomResponse,
    cc: TpmCc::StirRandom,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {}
}
