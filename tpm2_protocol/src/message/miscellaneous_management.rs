// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 26.2 `TPM2_PP_Commands`
//! 26.3 `TPM2_SetAlgorithmSet`

use crate::{
    data::{TpmCc, TpmlCc},
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPpCommandsCommand,
    TpmCc::PpCommands,
    false,
    true,
    1,
    {
        pub set_list: TpmlCc,
        pub clear_list: TpmlCc,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPpCommandsResponse,
    TpmCc::PpCommands,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmSetAlgorithmSetCommand,
    TpmCc::SetAlgorithmSet,
    false,
    true,
    1,
    {
        pub algorithm_set: u32,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmSetAlgorithmSetResponse,
    TpmCc::SetAlgorithmSet,
    false,
    true,
    {}
}
