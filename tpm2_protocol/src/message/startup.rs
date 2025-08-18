// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    data::{TpmCc, TpmSu},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmStartupCommand,
    TpmCc::Startup,
    true,
    false,
    0,
    {
        pub startup_type: TpmSu,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmStartupResponse,
    TpmCc::Startup,
    true,
    false,
    0,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmShutdownCommand,
    TpmCc::Shutdown,
    true,
    true,
    0,
    {
        pub shutdown_type: TpmSu,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmShutdownResponse,
    TpmCc::Shutdown,
    true,
    true,
    0,
    {}
}
