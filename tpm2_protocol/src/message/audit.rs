// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 21.2 `TPM2_SetCommandCodeAuditStatus`

use crate::{
    data::{TpmCc, TpmiAlgHash, TpmlCc},
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmSetCommandCodeAuditStatusCommand,
    cc: TpmCc::SetCommandCodeAuditStatus,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub audit_alg: TpmiAlgHash,
        pub set_list: TpmlCc,
        pub clear_list: TpmlCc,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmSetCommandCodeAuditStatusResponse,
    cc: TpmCc::SetCommandCodeAuditStatus,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}
