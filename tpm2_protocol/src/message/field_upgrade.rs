// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 27 Field Upgrade

use crate::{
    data::{Tpm2bDigest, TpmCc, TpmtHa, TpmtSignature},
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmFieldUpgradeStartCommand,
    TpmCc::FieldUpgradeStart,
    false,
    true,
    2,
    {
        pub fu_digest: Tpm2bDigest,
        pub manifest_signature: TpmtSignature,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmFieldUpgradeStartResponse,
    TpmCc::FieldUpgradeStart,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmFieldUpgradeDataCommand,
    TpmCc::FieldUpgradeData,
    true,
    true,
    0,
    {
        pub fu_data: crate::data::Tpm2bMaxBuffer,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmFieldUpgradeDataResponse,
    TpmCc::FieldUpgradeData,
    true,
    true,
    {
        pub next_digest: TpmtHa,
        pub first_digest: TpmtHa,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmFirmwareReadCommand,
    TpmCc::FirmwareRead,
    true,
    true,
    0,
    {
        pub sequence_number: u32,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmFirmwareReadResponse,
    TpmCc::FirmwareRead,
    true,
    true,
    {
        pub fu_data: crate::data::Tpm2bMaxBuffer,
    }
}
