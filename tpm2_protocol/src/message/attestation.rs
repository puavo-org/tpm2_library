// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 18 Attestation Commands

use crate::{
    data::{
        Tpm2bAttest, Tpm2bData, Tpm2bDigest, TpmCc, TpmlPcrSelection, TpmtSignature, TpmtTkCreation,
    },
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmCertifyCommand,
    cc: TpmCc::Certify,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub object_handle: crate::data::TpmiDhObject,
        pub sign_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmCertifyResponse,
    cc: TpmCc::Certify,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub certify_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmCertifyCreationCommand,
    cc: TpmCc::CertifyCreation,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub sign_handle: crate::data::TpmiDhObject,
        pub object_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub creation_hash: Tpm2bDigest,
        pub in_scheme: TpmtSignature,
        pub creation_ticket: TpmtTkCreation,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmCertifyCreationResponse,
    cc: TpmCc::CertifyCreation,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub certify_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmQuoteCommand,
    cc: TpmCc::Quote,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub sign_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
        pub pcr_select: TpmlPcrSelection,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmQuoteResponse,
    cc: TpmCc::Quote,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub quoted: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmGetSessionAuditDigestCommand,
    cc: TpmCc::GetSessionAuditDigest,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub privacy_admin_handle: crate::data::TpmiRhHierarchy,
        pub sign_handle: crate::data::TpmiDhObject,
        pub session_handle: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetSessionAuditDigestResponse,
    cc: TpmCc::GetSessionAuditDigest,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub audit_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmGetCommandAuditDigestCommand,
    cc: TpmCc::GetCommandAuditDigest,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub privacy_admin_handle: crate::data::TpmiRhHierarchy,
        pub sign_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetCommandAuditDigestResponse,
    cc: TpmCc::GetCommandAuditDigest,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub audit_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmGetTimeCommand,
    cc: TpmCc::GetTime,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub privacy_admin_handle: crate::data::TpmiRhHierarchy,
        pub sign_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetTimeResponse,
    cc: TpmCc::GetTime,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub time_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}
