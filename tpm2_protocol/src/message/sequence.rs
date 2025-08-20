// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 17 Hash/HMAC/Event Sequences

use crate::{
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bMaxBuffer, TpmAlgId, TpmCc, TpmRh, TpmlDigestValues,
        TpmtTkHashcheck,
    },
    tpm_struct, TpmTransient,
};
use core::fmt::Debug;

use super::symmetric::TpmiAlgMacScheme;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmHmacStartCommand,
    cc: TpmCc::HmacStart,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub auth: Tpm2bAuth,
        pub hash_alg: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmHmacStartResponse,
    cc: TpmCc::HmacStart,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub sequence_handle: TpmTransient,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmMacStartCommand,
    cc: TpmCc::HmacStart,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub auth: Tpm2bAuth,
        pub in_scheme: TpmiAlgMacScheme,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmMacStartResponse,
    cc: TpmCc::HmacStart,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub sequence_handle: TpmTransient,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmHashSequenceStartCommand,
    cc: TpmCc::HashSequenceStart,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub auth: Tpm2bAuth,
        pub hash_alg: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmHashSequenceStartResponse,
    cc: TpmCc::HashSequenceStart,
    no_sessions: true,
    with_sessions: true,
    handles: {
        pub sequence_handle: TpmTransient,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmSequenceUpdateCommand,
    cc: TpmCc::SequenceUpdate,
    no_sessions: true,
    with_sessions: true,
    handles: {
        pub sequence_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub buffer: Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmSequenceUpdateResponse,
    cc: TpmCc::SequenceUpdate,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmSequenceCompleteCommand,
    cc: TpmCc::SequenceComplete,
    no_sessions: true,
    with_sessions: true,
    handles: {
        pub sequence_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub buffer: Tpm2bMaxBuffer,
        pub hierarchy: TpmRh,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmSequenceCompleteResponse,
    cc: TpmCc::SequenceComplete,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub result: Tpm2bDigest,
        pub validation: TpmtTkHashcheck,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmEventSequenceCompleteCommand,
    cc: TpmCc::EventSequenceComplete,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub pcr_handle: u32,
        pub sequence_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub buffer: Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEventSequenceCompleteResponse,
    cc: TpmCc::EventSequenceComplete,
    no_sessions: true,
    with_sessions: true,
    handles: {},
    parameters: {
        pub results: TpmlDigestValues,
    }
}
