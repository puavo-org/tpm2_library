// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 29 Clocks and Timers

use crate::{
    data::{TpmCc, TpmClockAdjust, TpmsTimeInfo},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmReadClockCommand,
    cc: TpmCc::ReadClock,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmReadClockResponse,
    cc: TpmCc::ReadClock,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub current_time: TpmsTimeInfo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmClockSetCommand,
    cc: TpmCc::ClockSet,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub new_time: u64,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmClockSetResponse,
    cc: TpmCc::ClockSet,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmClockRateAdjustCommand,
    cc: TpmCc::ClockRateAdjust,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub rate_adjust: TpmClockAdjust,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmClockRateAdjustResponse,
    cc: TpmCc::ClockRateAdjust,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}
