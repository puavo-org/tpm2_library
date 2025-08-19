// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 17 Hash/HMAC/Event Sequences

use crate::{
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bMaxBuffer, TpmAlgId, TpmCc, TpmRh, TpmlDigestValues,
        TpmtTkHashcheck,
    },
    tpm_response, tpm_struct, TpmTransient,
};
use core::fmt::Debug;

use super::symmetric::TpmiAlgMacScheme;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHmacStartCommand,
    TpmCc::HmacStart,
    false,
    true,
    1,
    {
        pub auth: Tpm2bAuth,
        pub hash_alg: TpmAlgId,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmHmacStartResponse,
    TpmCc::HmacStart,
    false,
    true,
    pub sequence_handle: TpmTransient,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmMacStartCommand,
    TpmCc::HmacStart,
    false,
    true,
    1,
    {
        pub auth: Tpm2bAuth,
        pub in_scheme: TpmiAlgMacScheme,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmMacStartResponse,
    TpmCc::HmacStart,
    false,
    true,
    pub sequence_handle: TpmTransient,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHashSequenceStartCommand,
    TpmCc::HashSequenceStart,
    true,
    true,
    0,
    {
        pub auth: Tpm2bAuth,
        pub hash_alg: TpmAlgId,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmHashSequenceStartResponse,
    TpmCc::HashSequenceStart,
    true,
    true,
    pub sequence_handle: TpmTransient,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSequenceUpdateCommand,
    TpmCc::SequenceUpdate,
    true,
    true,
    1,
    {
        pub buffer: Tpm2bMaxBuffer,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmSequenceUpdateResponse,
    TpmCc::SequenceUpdate,
    true,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSequenceCompleteCommand,
    TpmCc::SequenceComplete,
    true,
    true,
    1,
    {
        pub buffer: Tpm2bMaxBuffer,
        pub hierarchy: TpmRh,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSequenceCompleteResponse,
    TpmCc::SequenceComplete,
    true,
    true,
    {
        pub result: Tpm2bDigest,
        pub validation: TpmtTkHashcheck,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEventSequenceCompleteCommand,
    TpmCc::EventSequenceComplete,
    true,
    true,
    2,
    {
        pub buffer: Tpm2bMaxBuffer,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmEventSequenceCompleteResponse,
    TpmCc::EventSequenceComplete,
    true,
    true,
    {
        pub results: TpmlDigestValues,
    }
}
