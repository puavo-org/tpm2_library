// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 29 Clocks and Timers

use crate::{
    data::{TpmCc, TpmClockAdjust, TpmsTimeInfo},
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmReadClockCommand,
    TpmCc::ReadClock,
    true,
    false,
    0,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmReadClockResponse,
    TpmCc::ReadClock,
    true,
    false,
    0,
    {
        pub current_time: TpmsTimeInfo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClockSetCommand,
    TpmCc::ClockSet,
    false,
    true,
    1,
    {
        pub new_time: u64,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClockSetResponse,
    TpmCc::ClockSet,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClockRateAdjustCommand,
    TpmCc::ClockRateAdjust,
    false,
    true,
    1,
    {
        pub rate_adjust: TpmClockAdjust,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClockRateAdjustResponse,
    TpmCc::ClockRateAdjust,
    false,
    true,
    {}
}
