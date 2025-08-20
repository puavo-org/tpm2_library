// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 27 Field Upgrade

use crate::{
    data::{Tpm2bDigest, TpmCc, TpmtHa, TpmtSignature},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmFieldUpgradeStartCommand,
    cc: TpmCc::FieldUpgradeStart,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub authorization: crate::data::TpmiRhHierarchy,
        pub key_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub fu_digest: Tpm2bDigest,
        pub manifest_signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmFieldUpgradeStartResponse,
    cc: TpmCc::FieldUpgradeStart,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmFieldUpgradeDataCommand,
    cc: TpmCc::FieldUpgradeData,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub fu_data: crate::data::Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmFieldUpgradeDataResponse,
    cc: TpmCc::FieldUpgradeData,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub next_digest: TpmtHa,
        pub first_digest: TpmtHa,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmFirmwareReadCommand,
    cc: TpmCc::FirmwareRead,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub sequence_number: u32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmFirmwareReadResponse,
    cc: TpmCc::FirmwareRead,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub fu_data: crate::data::Tpm2bMaxBuffer,
    }
}
