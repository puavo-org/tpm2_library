// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 10.2 `TPM2_SelfTest`
//! 10.3 `TPM2_IncrementalSelfTest`
//! 10.4 `TPM2_GetTestResult`

use crate::{
    data::{Tpm2bMaxBuffer, TpmCc, TpmRc, TpmiYesNo, TpmlAlg},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmSelfTestCommand,
    cc: TpmCc::SelfTest,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub full_test: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmSelfTestResponse,
    cc: TpmCc::SelfTest,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmIncrementalSelfTestCommand,
    cc: TpmCc::IncrementalSelfTest,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub to_test: TpmlAlg,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmIncrementalSelfTestResponse,
    cc: TpmCc::IncrementalSelfTest,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub to_do_list: TpmlAlg,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmGetTestResultCommand,
    cc: TpmCc::GetTestResult,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetTestResultResponse,
    cc: TpmCc::GetTestResult,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub out_data: Tpm2bMaxBuffer,
        pub test_result: TpmRc,
    }
}
