// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 21.2 `TPM2_SetCommandCodeAuditStatus`

use crate::{
    data::{TpmCc, TpmiAlgHash, TpmlCc},
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSetCommandCodeAuditStatusCommand,
    TpmCc::SetCommandCodeAuditStatus,
    false,
    true,
    1,
    {
        pub audit_alg: TpmiAlgHash,
        pub set_list: TpmlCc,
        pub clear_list: TpmlCc,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmSetCommandCodeAuditStatusResponse,
    TpmCc::SetCommandCodeAuditStatus,
    false,
    true,
    {}
}
