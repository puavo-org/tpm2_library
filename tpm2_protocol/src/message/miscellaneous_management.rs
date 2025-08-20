// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 26.2 `TPM2_PP_Commands`
//! 26.3 `TPM2_SetAlgorithmSet`

use crate::{
    data::{TpmCc, TpmlCc},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPpCommandsCommand,
    cc: TpmCc::PpCommands,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub set_list: TpmlCc,
        pub clear_list: TpmlCc,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPpCommandsResponse,
    cc: TpmCc::PpCommands,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmSetAlgorithmSetCommand,
    cc: TpmCc::SetAlgorithmSet,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub algorithm_set: u32,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmSetAlgorithmSetResponse,
    cc: TpmCc::SetAlgorithmSet,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}
