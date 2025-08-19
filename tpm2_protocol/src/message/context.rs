// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 28.2 `TPM2_ContextSave`
//! 28.3 `TPM2_ContextLoad`
//! 28.4 `TPM2_FlushContext`
//! 28.5 `TPM2_EvictControl`

use crate::{
    data::{TpmCc, TpmsContext},
    tpm_response, tpm_struct, TpmPersistent, TpmTransient,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmContextLoadCommand,
    TpmCc::ContextLoad,
    true,
    false,
    0,
    {
        pub context: TpmsContext,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmContextLoadResponse,
    TpmCc::ContextLoad,
    true,
    false,
    0,
    {
        pub loaded_handle: TpmTransient,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmContextSaveCommand,
    TpmCc::ContextSave,
    true,
    false,
    1,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmContextSaveResponse,
    TpmCc::ContextSave,
    true,
    false,
    0,
    {
        pub context: TpmsContext,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmFlushContextCommand,
    TpmCc::FlushContext,
    true,
    false,
    0,
    {
        pub flush_handle: u32,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmFlushContextResponse,
    TpmCc::FlushContext,
    true,
    false,
    0,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEvictControlCommand,
    TpmCc::EvictControl,
    false,
    true,
    2,
    {
        pub persistent_handle: TpmPersistent,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmEvictControlResponse,
    TpmCc::EvictControl,
    false,
    true,
    {}
}
