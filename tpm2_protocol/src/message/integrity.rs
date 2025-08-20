// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 22 Integrity Collection (PCR)

use crate::{
    data::{
        Tpm2bDigest, Tpm2bEvent, TpmAlgId, TpmCc, TpmRh, TpmiYesNo, TpmlDigest, TpmlDigestValues,
        TpmlPcrSelection,
    },
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPcrEventCommand,
    cc: TpmCc::PcrEvent,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub pcr_handle: u32,
    },
    parameters: {
        pub event_data: Tpm2bEvent,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmPcrEventResponse,
    cc: TpmCc::PcrEvent,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub digests: TpmlDigestValues,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPcrReadCommand,
    cc: TpmCc::PcrRead,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub pcr_selection_in: TpmlPcrSelection,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmPcrReadResponse,
    cc: TpmCc::PcrRead,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub pcr_update_counter: u32,
        pub pcr_selection_out: TpmlPcrSelection,
        pub pcr_values: TpmlDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPcrExtendCommand,
    cc: TpmCc::PcrExtend,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub pcr_handle: u32,
    },
    parameters: {
        pub digests: TpmlDigestValues,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPcrExtendResponse,
    cc: TpmCc::PcrExtend,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPcrAllocateCommand,
    cc: TpmCc::PcrAllocate,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub pcr_allocation: TpmlPcrSelection,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmPcrAllocateResponse,
    cc: TpmCc::PcrAllocate,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub allocation_success: TpmiYesNo,
        pub max_pcr: u32,
        pub size_needed: u32,
        pub size_available: u32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPcrSetAuthPolicyCommand,
    cc: TpmCc::PcrSetAuthPolicy,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub auth_policy: Tpm2bDigest,
        pub hash_alg: TpmAlgId,
        pub pcr_num: TpmRh,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPcrSetAuthPolicyResponse,
    cc: TpmCc::PcrSetAuthPolicy,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPcrSetAuthValueCommand,
    cc: TpmCc::PcrSetAuthValue,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub pcr_handle: u32,
    },
    parameters: {
        pub auth: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPcrSetAuthValueResponse,
    cc: TpmCc::PcrSetAuthValue,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPcrResetCommand,
    cc: TpmCc::PcrReset,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub pcr_handle: u32,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPcrResetResponse,
    cc: TpmCc::PcrReset,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}
