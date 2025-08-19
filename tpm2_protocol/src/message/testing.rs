// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 10.2 `TPM2_SelfTest`
//! 10.3 `TPM2_IncrementalSelfTest`
//! 10.4 `TPM2_GetTestResult`

use crate::{
    data::{Tpm2bMaxBuffer, TpmCc, TpmRc, TpmiYesNo, TpmlAlg},
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmSelfTestCommand,
    TpmCc::SelfTest,
    true,
    true,
    0,
    {
        pub full_test: TpmiYesNo,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmSelfTestResponse,
    TpmCc::SelfTest,
    true,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmIncrementalSelfTestCommand,
    TpmCc::IncrementalSelfTest,
    true,
    true,
    0,
    {
        pub to_test: TpmlAlg,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmIncrementalSelfTestResponse,
    TpmCc::IncrementalSelfTest,
    true,
    true,
    {
        pub to_do_list: TpmlAlg,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmGetTestResultCommand,
    TpmCc::GetTestResult,
    true,
    true,
    0,
    {}
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetTestResultResponse,
    TpmCc::GetTestResult,
    true,
    true,
    {
        pub out_data: Tpm2bMaxBuffer,
        pub test_result: TpmRc,
    }
}
