// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 22 Integrity Collection (PCR)

use crate::{
    data::{
        Tpm2b, Tpm2bDigest, TpmAlgId, TpmCc, TpmRh, TpmiYesNo, TpmlDigest, TpmlDigestValues,
        TpmlPcrSelection,
    },
    tpm_response, tpm_struct, TpmSized,
};
use core::{convert::TryFrom, fmt::Debug};

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrEventCommand,
    TpmCc::PcrEvent,
    false,
    true,
    1,
    {
        pub event_data: Tpm2b,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPcrReadCommand,
    TpmCc::PcrRead,
    true,
    false,
    0,
    {
        pub pcr_selection_in: TpmlPcrSelection,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPcrReadResponse,
    TpmCc::PcrRead,
    true,
    false,
    0,
    {
        pub pcr_update_counter: u32,
        pub pcr_selection_out: TpmlPcrSelection,
        pub pcr_values: TpmlDigest,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPcrEventResponse,
    TpmCc::PcrEvent,
    false,
    true,
    {
        pub digests: TpmlDigestValues,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrExtendCommand,
    TpmCc::PcrExtend,
    false,
    true,
    1,
    {
        pub digests: TpmlDigestValues,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPcrExtendResponse,
    TpmCc::PcrExtend,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrAllocateCommand,
    TpmCc::PcrAllocate,
    false,
    true,
    1,
    {
        pub pcr_allocation: TpmlPcrSelection,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrAllocateResponse,
    TpmCc::PcrAllocate,
    false,
    true,
    {
        pub allocation_success: TpmiYesNo,
        pub max_pcr: u32,
        pub size_needed: u32,
        pub size_available: u32,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrSetAuthPolicyCommand,
    TpmCc::PcrSetAuthPolicy,
    false,
    true,
    1,
    {
        pub auth_policy: Tpm2bDigest,
        pub hash_alg: TpmAlgId,
        pub pcr_num: TpmRh,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPcrSetAuthPolicyResponse,
    TpmCc::PcrSetAuthPolicy,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrSetAuthValueCommand,
    TpmCc::PcrSetAuthValue,
    false,
    true,
    1,
    {
        pub auth: Tpm2bDigest,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPcrSetAuthValueResponse,
    TpmCc::PcrSetAuthValue,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPcrResetCommand,
    TpmCc::PcrReset,
    false,
    true,
    1,
    {}
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPcrResetResponse,
    TpmCc::PcrReset,
    false,
    true,
    {}
);
