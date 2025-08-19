// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 28 Policy Commands

use crate::{
    data::{
        Tpm2b, Tpm2bDigest, Tpm2bMaxBuffer, Tpm2bName, Tpm2bNonce, Tpm2bTimeout, TpmAlgId, TpmCap,
        TpmCc, TpmEo, TpmaLocality, TpmiYesNo, TpmlDigest, TpmlPcrSelection, TpmtSignature,
        TpmtTkAuth, TpmtTkVerified,
    },
    tpm_response, tpm_struct,
};
use core::fmt::Debug;

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyAuthValueCommand,
    TpmCc::PolicyAuthValue,
    false,
    true,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyCommandCodeCommand,
    TpmCc::PolicyCommandCode,
    false,
    true,
    1,
    {
        pub code: TpmCc,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyGetDigestCommand,
    TpmCc::PolicyGetDigest,
    false,
    true,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPolicyOrCommand,
    TpmCc::PolicyOR,
    false,
    true,
    1,
    {
        pub p_hash_list: TpmlDigest,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyPasswordCommand,
    TpmCc::PolicyPassword,
    false,
    true,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPolicyPcrCommand,
    TpmCc::PolicyPcr,
    false,
    true,
    1,
    {
        pub pcr_digest: Tpm2bDigest,
        pub pcrs: TpmlPcrSelection,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyRestartCommand,
    TpmCc::PolicyRestart,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPolicySecretCommand,
    TpmCc::PolicySecret,
    false,
    true,
    2,
    {
        pub nonce_tpm: Tpm2b,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: Tpm2b,
        pub expiration: i32,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPolicyGetDigestResponse,
    TpmCc::PolicyGetDigest,
    false,
    true,
    {
        pub policy_digest: Tpm2bDigest,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyAuthValueResponse,
    TpmCc::PolicyAuthValue,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyCommandCodeResponse,
    TpmCc::PolicyCommandCode,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyOrResponse,
    TpmCc::PolicyOR,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyPasswordResponse,
    TpmCc::PolicyPassword,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyPcrResponse,
    TpmCc::PolicyPcr,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyRestartResponse,
    TpmCc::PolicyRestart,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicySecretResponse,
    TpmCc::PolicySecret,
    false,
    true,
    0,
    {}
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicySignedCommand,
    TpmCc::PolicySigned,
    false,
    true,
    2,
    {
        pub nonce_tpm: Tpm2bNonce,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: Tpm2bNonce,
        pub expiration: i32,
        pub auth: TpmtSignature,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicySignedResponse,
    TpmCc::PolicySigned,
    false,
    true,
    {
        pub timeout: Tpm2bTimeout,
        pub policy_ticket: TpmtTkAuth,
    }
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyTicketCommand,
    TpmCc::PolicyTicket,
    false,
    true,
    1,
    {
        pub timeout: Tpm2bTimeout,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: Tpm2bNonce,
        pub auth_name: Tpm2bName,
        pub ticket: TpmtTkAuth,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyTicketResponse,
    TpmCc::PolicyTicket,
    false,
    true,
    {}
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmPolicyLocalityCommand,
    TpmCc::PolicyLocality,
    false,
    true,
    1,
    {
        pub locality: TpmaLocality,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyLocalityResponse,
    TpmCc::PolicyLocality,
    false,
    true,
    {}
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyCpHashCommand,
    TpmCc::PolicyCpHash,
    false,
    true,
    1,
    {
        pub cp_hash_a: Tpm2bDigest,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyCpHashResponse,
    TpmCc::PolicyCpHash,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyPhysicalPresenceCommand,
    TpmCc::PolicyPhysicalPresence,
    false,
    true,
    1,
    {}
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyPhysicalPresenceResponse,
    TpmCc::PolicyPhysicalPresence,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSetPrimaryPolicyCommand,
    TpmCc::SetPrimaryPolicy,
    false,
    true,
    1,
    {
        pub auth_policy: Tpm2bDigest,
        pub hash_alg: TpmAlgId,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmSetPrimaryPolicyResponse,
    TpmCc::SetPrimaryPolicy,
    false,
    true,
    {}
);

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyNvCommand,
    TpmCc::PolicyNv,
    false,
    true,
    3,
    {
        pub operand_b: Tpm2bMaxBuffer,
        pub offset: u16,
        pub operation: TpmEo,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyNvResponse,
    TpmCc::PolicyNv,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyCounterTimerCommand,
    TpmCc::PolicyCounterTimer,
    false,
    true,
    1,
    {
        pub operand_b: Tpm2bMaxBuffer,
        pub offset: u16,
        pub operation: TpmEo,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyCounterTimerResponse,
    TpmCc::PolicyCounterTimer,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyNameHashCommand,
    TpmCc::PolicyNameHash,
    false,
    true,
    1,
    {
        pub name_hash: Tpm2bDigest,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyNameHashResponse,
    TpmCc::PolicyNameHash,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyDuplicationSelectCommand,
    TpmCc::PolicyDuplicationSelect,
    false,
    true,
    1,
    {
        pub object_name: Tpm2bName,
        pub new_parent_name: Tpm2bName,
        pub include_object: TpmiYesNo,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyDuplicationSelectResponse,
    TpmCc::PolicyDuplicationSelect,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyAuthorizeCommand,
    TpmCc::PolicyAuthorize,
    false,
    true,
    1,
    {
        pub approved_policy: Tpm2bDigest,
        pub policy_ref: Tpm2bNonce,
        pub key_sign: Tpm2bName,
        pub check_ticket: TpmtTkVerified,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyAuthorizeResponse,
    TpmCc::PolicyAuthorize,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmPolicyNvWrittenCommand,
    TpmCc::PolicyNvWritten,
    false,
    true,
    1,
    {
        pub written_set: TpmiYesNo,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyNvWrittenResponse,
    TpmCc::PolicyNvWritten,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyTemplateCommand,
    TpmCc::PolicyTemplate,
    false,
    true,
    1,
    {
        pub template_hash: Tpm2bDigest,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyTemplateResponse,
    TpmCc::PolicyTemplate,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyAuthorizeNvCommand,
    TpmCc::PolicyAuthorizeNv,
    false,
    true,
    3,
    {}
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyAuthorizeNvResponse,
    TpmCc::PolicyAuthorizeNv,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyCapabilityCommand,
    TpmCc::PolicyCapability,
    false,
    true,
    1,
    {
        pub capability: TpmCap,
        pub property: u32,
        pub op: TpmEo,
        pub operand_b: Tpm2bMaxBuffer,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyCapabilityResponse,
    TpmCc::PolicyCapability,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyParametersCommand,
    TpmCc::PolicyParameters,
    false,
    true,
    1,
    {
        pub p_hash: Tpm2bDigest,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyParametersResponse,
    TpmCc::PolicyParameters,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyTransportSpdmCommand,
    TpmCc::PolicyTransportSpdm,
    false,
    true,
    1,
    {
        pub req_key_name: Tpm2bName,
        pub tpm_key_name: Tpm2bName,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyTransportSpdmResponse,
    TpmCc::PolicyTransportSpdm,
    false,
    true,
    {}
}
