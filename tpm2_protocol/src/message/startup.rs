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
    kind: Command,
    name: TpmStartupCommand,
    cc: TpmCc::Startup,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub startup_type: TpmSu,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmStartupResponse,
    cc: TpmCc::Startup,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmShutdownCommand,
    cc: TpmCc::Shutdown,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub shutdown_type: TpmSu,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmShutdownResponse,
    cc: TpmCc::Shutdown,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {}
}
