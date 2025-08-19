// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    data::{
        Tpm2b, Tpm2bAttest, Tpm2bAuth, Tpm2bCreationData, Tpm2bData, Tpm2bDigest,
        Tpm2bEncryptedSecret, Tpm2bMaxBuffer, Tpm2bName, Tpm2bPrivate, Tpm2bPublic,
        Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmAlgId, TpmCap, TpmCc, TpmRc, TpmRh, TpmSe,
        TpmiYesNo, TpmlAlg, TpmlPcrSelection, TpmsAuthCommand, TpmsAuthResponse,
        TpmsCapabilityData, TpmsContext, TpmtSignature, TpmtSymDef, TpmtSymDefObject,
        TpmtTkCreation, TpmtTkHashcheck, TpmtTkVerified,
    },
    tpm_dispatch, tpm_response, tpm_struct, TpmBuild, TpmList, TpmParse, TpmPersistent, TpmSession,
    TpmTransient,
};
use core::fmt::Debug;

pub mod asymmetric;
pub mod attached;
pub mod attestation;
pub mod build;
pub mod clocks_and_timers;
pub mod enhanced_authorization;
pub mod field_upgrade;
pub mod integrity;
pub mod non_volatile;
pub mod object;
pub mod parse;
pub mod sequence;
pub mod startup;

pub use asymmetric::*;
pub use attached::*;
pub use attestation::*;
pub use build::*;
pub use clocks_and_timers::*;
pub use enhanced_authorization::*;
pub use field_upgrade::*;
pub use integrity::*;
pub use non_volatile::*;
pub use object::*;
pub use parse::*;
pub use sequence::*;
pub use startup::*;

/// The maximum number of handles a command can have.
pub const MAX_HANDLES: usize = 8;
/// The maximum number of sessions a command can have.
pub const MAX_SESSIONS: usize = 8;

/// A fixed-capacity list for TPM handles.
pub type TpmHandles = TpmList<u32, MAX_HANDLES>;
/// A fixed-capacity list for command authorization sessions.
pub type TpmAuthCommands = TpmList<TpmsAuthCommand, MAX_SESSIONS>;
/// A fixed-capacity list for response authorization sessions.
pub type TpmAuthResponses = TpmList<TpmsAuthResponse, MAX_SESSIONS>;

/// A trait for TPM commands and responses that provides header information.
pub trait TpmHeader: TpmBuild + TpmParse + Debug {
    const COMMAND: TpmCc;
    const NO_SESSIONS: bool;
    const WITH_SESSIONS: bool;
    const HANDLES: usize;
}

pub const TPM_HEADER_SIZE: usize = 10;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmContextLoadCommand,
    TpmCc::ContextLoad,
    true,
    false,
    0,
    {
        pub context: TpmsContext,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmContextSaveCommand,
    TpmCc::ContextSave,
    true,
    false,
    1,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmDictionaryAttackLockResetCommand,
    TpmCc::DictionaryAttackLockReset,
    false,
    true,
    1,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmFlushContextCommand,
    TpmCc::FlushContext,
    true,
    false,
    0,
    {
        pub flush_handle: u32,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmCreatePrimaryCommand,
    TpmCc::CreatePrimary,
    false,
    true,
    1,
    {
        pub in_sensitive: Tpm2bSensitiveCreate,
        pub in_public: Tpm2bPublic,
        pub outside_info: Tpm2b,
        pub creation_pcr: TpmlPcrSelection,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEvictControlCommand,
    TpmCc::EvictControl,
    false,
    true,
    2,
    {
        pub persistent_handle: TpmPersistent,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetCapabilityCommand,
    TpmCc::GetCapability,
    true,
    true,
    0,
    {
        pub cap: TpmCap,
        pub property: u32,
        pub property_count: u32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHashCommand,
    TpmCc::Hash,
    true,
    false,
    0,
    {
        pub data: Tpm2bMaxBuffer,
        pub hash_alg: TpmAlgId,
        pub hierarchy: TpmRh,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmImportCommand,
    TpmCc::Import,
    false,
    true,
    1,
    {
        pub encryption_key: Tpm2b,
        pub object_public: Tpm2bPublic,
        pub duplicate: Tpm2bPrivate,
        pub in_sym_seed: Tpm2bEncryptedSecret,
        pub symmetric_alg: TpmtSymDef,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmStartAuthSessionCommand,
    TpmCc::StartAuthSession,
    true,
    true,
    2,
    {
        pub nonce_caller: Tpm2b,
        pub encrypted_salt: Tpm2b,
        pub session_type: TpmSe,
        pub symmetric: TpmtSymDefObject,
        pub auth_hash: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmVendorTcgTestCommand,
    TpmCc::VendorTcgTest,
    true,
    false,
    0,
    {
        pub input_data: Tpm2bData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmContextLoadResponse,
    TpmCc::ContextLoad,
    true,
    false,
    0,
    {
        pub loaded_handle: TpmTransient,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmContextSaveResponse,
    TpmCc::ContextSave,
    true,
    false,
    0,
    {
        pub context: TpmsContext,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHashResponse,
    TpmCc::Hash,
    true,
    false,
    0,
    {
        pub out_hash: Tpm2bDigest,
        pub validation: TpmtTkHashcheck,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmImportResponse,
    TpmCc::Import,
    false,
    true,
    0,
    {
        pub out_private: Tpm2bPrivate,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmStartAuthSessionResponse,
    TpmCc::StartAuthSession,
    true,
    false,
    0,
    {
        pub session_handle: TpmSession,
        pub nonce_tpm: Tpm2b,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmVendorTcgTestResponse,
    TpmCc::VendorTcgTest,
    true,
    false,
    0,
    {
        pub output_data: Tpm2bData,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCreatePrimaryResponse,
    TpmCc::CreatePrimary,
    false,
    true,
    pub object_handle: TpmTransient,
    {
        pub out_public: Tpm2bPublic,
        pub creation_data: Tpm2bCreationData,
        pub creation_hash: Tpm2bDigest,
        pub creation_ticket: TpmtTkCreation,
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmDictionaryAttackLockResetResponse,
    TpmCc::DictionaryAttackLockReset,
    false,
    true,
    0,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmEvictControlResponse,
    TpmCc::EvictControl,
    false,
    true,
    0,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmFlushContextResponse,
    TpmCc::FlushContext,
    true,
    false,
    0,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetCapabilityResponse,
    TpmCc::GetCapability,
    true,
    false,
    0,
    {
        pub more_data: TpmiYesNo,
        pub capability_data: TpmsCapabilityData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmQuoteCommand,
    TpmCc::Quote,
    false,
    true,
    1,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
        pub pcr_select: TpmlPcrSelection,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmQuoteResponse,
    TpmCc::Quote,
    false,
    true,
    {
        pub quoted: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSignCommand,
    TpmCc::Sign,
    false,
    true,
    1,
    {
        pub digest: Tpm2bDigest,
        pub in_scheme: TpmtSignature,
        pub validation: TpmtTkHashcheck,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSignResponse,
    TpmCc::Sign,
    false,
    true,
    {
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmVerifySignatureCommand,
    TpmCc::VerifySignature,
    true,
    false,
    1,
    {
        pub digest: Tpm2bDigest,
        pub signature: TpmtSignature,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmVerifySignatureResponse,
    TpmCc::VerifySignature,
    true,
    false,
    {
        pub validation: TpmtTkVerified,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmSelfTestCommand,
    TpmCc::SelfTest,
    true,
    true,
    0,
    {
        pub full_test: TpmiYesNo,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmSelfTestResponse,
    TpmCc::SelfTest,
    true,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmIncrementalSelfTestCommand,
    TpmCc::IncrementalSelfTest,
    true,
    true,
    0,
    {
        pub to_test: TpmlAlg,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmIncrementalSelfTestResponse,
    TpmCc::IncrementalSelfTest,
    true,
    true,
    {
        pub to_do_list: TpmlAlg,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmGetTestResultCommand,
    TpmCc::GetTestResult,
    true,
    true,
    0,
    {}
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetTestResultResponse,
    TpmCc::GetTestResult,
    true,
    true,
    {
        pub out_data: Tpm2bMaxBuffer,
        pub test_result: TpmRc,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmDuplicateCommand,
    TpmCc::Duplicate,
    false,
    true,
    2,
    {
        pub encryption_key_in: Tpm2bData,
        pub symmetric_alg: TpmtSymDefObject,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmDuplicateResponse,
    TpmCc::Duplicate,
    false,
    true,
    {
        pub encryption_key_out: Tpm2bData,
        pub duplicate: Tpm2bPrivate,
        pub out_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRewrapCommand,
    TpmCc::Rewrap,
    false,
    true,
    2,
    {
        pub in_duplicate: Tpm2bPrivate,
        pub name: Tpm2bName,
        pub in_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRewrapResponse,
    TpmCc::Rewrap,
    false,
    true,
    {
        pub out_duplicate: Tpm2bPrivate,
        pub out_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEncryptDecrypt2Command,
    TpmCc::EncryptDecrypt2,
    false,
    true,
    1,
    {
        pub in_data: Tpm2bMaxBuffer,
        pub decrypt: TpmiYesNo,
        pub mode: TpmAlgId,
        pub iv_in: Tpm2b,
    }
}

tpm_response! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEncryptDecrypt2Response,
    TpmCc::EncryptDecrypt2,
    false,
    true,
    {
        pub out_data: Tpm2bMaxBuffer,
        pub iv_out: Tpm2b,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmGetRandomCommand,
    TpmCc::GetRandom,
    true,
    true,
    0,
    {
        pub bytes_requested: u16,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmGetRandomResponse,
    TpmCc::GetRandom,
    true,
    true,
    {
        pub random_bytes: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmStirRandomCommand,
    TpmCc::StirRandom,
    true,
    true,
    0,
    {
        pub in_data: Tpm2bSensitiveData,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmStirRandomResponse,
    TpmCc::StirRandom,
    true,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHierarchyControlCommand,
    TpmCc::HierarchyControl,
    false,
    true,
    1,
    {
        pub enable: TpmRh,
        pub state: TpmiYesNo,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmHierarchyControlResponse,
    TpmCc::HierarchyControl,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangePpsCommand,
    TpmCc::ChangePps,
    false,
    true,
    1,
    {}
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangePpsResponse,
    TpmCc::ChangePps,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangeEpsCommand,
    TpmCc::ChangeEps,
    false,
    true,
    1,
    {}
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangeEpsResponse,
    TpmCc::ChangeEps,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClearCommand,
    TpmCc::Clear,
    false,
    true,
    1,
    {}
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClearResponse,
    TpmCc::Clear,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmClearControlCommand,
    TpmCc::ClearControl,
    false,
    true,
    1,
    {
        pub disable: TpmiYesNo,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClearControlResponse,
    TpmCc::ClearControl,
    false,
    true,
    {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHierarchyChangeAuthCommand,
    TpmCc::HierarchyChangeAuth,
    false,
    true,
    1,
    {
        pub new_auth: Tpm2bAuth,
    }
}

tpm_response! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmHierarchyChangeAuthResponse,
    TpmCc::HierarchyChangeAuth,
    false,
    true,
    {}
}

tpm_dispatch! {
    (TpmNvUndefineSpaceSpecialCommand, TpmNvUndefineSpaceSpecialResponse, NvUndefineSpaceSpecial),
    (TpmEvictControlCommand, TpmEvictControlResponse, EvictControl),
    (TpmHierarchyControlCommand, TpmHierarchyControlResponse, HierarchyControl),
    (TpmNvUndefineSpaceCommand, TpmNvUndefineSpaceResponse, NvUndefineSpace),
    (TpmChangeEpsCommand, TpmChangeEpsResponse, ChangeEps),
    (TpmChangePpsCommand, TpmChangePpsResponse, ChangePps),
    (TpmClearCommand, TpmClearResponse, Clear),
    (TpmClearControlCommand, TpmClearControlResponse, ClearControl),
    (TpmClockSetCommand, TpmClockSetResponse, ClockSet),
    (TpmHierarchyChangeAuthCommand, TpmHierarchyChangeAuthResponse, HierarchyChangeAuth),
    (TpmNvDefineSpaceCommand, TpmNvDefineSpaceResponse, NvDefineSpace),
    (TpmPcrAllocateCommand, TpmPcrAllocateResponse, PcrAllocate),
    (TpmPcrSetAuthPolicyCommand, TpmPcrSetAuthPolicyResponse, PcrSetAuthPolicy),
    (TpmSetPrimaryPolicyCommand, TpmSetPrimaryPolicyResponse, SetPrimaryPolicy),
    (TpmFieldUpgradeStartCommand, TpmFieldUpgradeStartResponse, FieldUpgradeStart),
    (TpmClockRateAdjustCommand, TpmClockRateAdjustResponse, ClockRateAdjust),
    (TpmCreatePrimaryCommand, TpmCreatePrimaryResponse, CreatePrimary),
    (TpmNvGlobalWriteLockCommand, TpmNvGlobalWriteLockResponse, NvGlobalWriteLock),
    (TpmGetCommandAuditDigestCommand, TpmGetCommandAuditDigestResponse, GetCommandAuditDigest),
    (TpmNvIncrementCommand, TpmNvIncrementResponse, NvIncrement),
    (TpmNvSetBitsCommand, TpmNvSetBitsResponse, NvSetBits),
    (TpmNvExtendCommand, TpmNvExtendResponse, NvExtend),
    (TpmNvWriteCommand, TpmNvWriteResponse, NvWrite),
    (TpmNvWriteLockCommand, TpmNvWriteLockResponse, NvWriteLock),
    (TpmDictionaryAttackLockResetCommand, TpmDictionaryAttackLockResetResponse, DictionaryAttackLockReset),
    (TpmNvChangeAuthCommand, TpmNvChangeAuthResponse, NvChangeAuth),
    (TpmPcrEventCommand, TpmPcrEventResponse, PcrEvent),
    (TpmPcrResetCommand, TpmPcrResetResponse, PcrReset),
    (TpmSequenceCompleteCommand, TpmSequenceCompleteResponse, SequenceComplete),
    (TpmFieldUpgradeDataCommand, TpmFieldUpgradeDataResponse, FieldUpgradeData),
    (TpmIncrementalSelfTestCommand, TpmIncrementalSelfTestResponse, IncrementalSelfTest),
    (TpmSelfTestCommand, TpmSelfTestResponse, SelfTest),
    (TpmStartupCommand, TpmStartupResponse, Startup),
    (TpmShutdownCommand, TpmShutdownResponse, Shutdown),
    (TpmStirRandomCommand, TpmStirRandomResponse, StirRandom),
    (TpmActivateCredentialCommand, TpmActivateCredentialResponse, ActivateCredential),
    (TpmCertifyCommand, TpmCertifyResponse, Certify),
    (TpmPolicyNvCommand, TpmPolicyNvResponse, PolicyNv),
    (TpmCertifyCreationCommand, TpmCertifyCreationResponse, CertifyCreation),
    (TpmDuplicateCommand, TpmDuplicateResponse, Duplicate),
    (TpmGetTimeCommand, TpmGetTimeResponse, GetTime),
    (TpmGetSessionAuditDigestCommand, TpmGetSessionAuditDigestResponse, GetSessionAuditDigest),
    (TpmNvReadCommand, TpmNvReadResponse, NvRead),
    (TpmNvReadLockCommand, TpmNvReadLockResponse, NvReadLock),
    (TpmObjectChangeAuthCommand, TpmObjectChangeAuthResponse, ObjectChangeAuth),
    (TpmPolicySecretCommand, TpmPolicySecretResponse, PolicySecret),
    (TpmRewrapCommand, TpmRewrapResponse, Rewrap),
    (TpmCreateCommand, TpmCreateResponse, Create),
    (TpmEcdhZGenCommand, TpmEcdhZGenResponse, EcdhZGen),
    (TpmZGen2PhaseCommand, TpmZGen2PhaseResponse, ZGen2Phase),
    (TpmImportCommand, TpmImportResponse, Import),
    (TpmLoadCommand, TpmLoadResponse, Load),
    (TpmQuoteCommand, TpmQuoteResponse, Quote),
    (TpmRsaDecryptCommand, TpmRsaDecryptResponse, RsaDecrypt),
    (TpmEccEncryptCommand, TpmEccEncryptResponse, EccEncrypt),
    (TpmEccDecryptCommand, TpmEccDecryptResponse, EccDecrypt),
    (TpmSequenceUpdateCommand, TpmSequenceUpdateResponse, SequenceUpdate),
    (TpmSignCommand, TpmSignResponse, Sign),
    (TpmUnsealCommand, TpmUnsealResponse, Unseal),
    (TpmPolicySignedCommand, TpmPolicySignedResponse, PolicySigned),
    (TpmContextLoadCommand, TpmContextLoadResponse, ContextLoad),
    (TpmContextSaveCommand, TpmContextSaveResponse, ContextSave),
    (TpmEcdhKeyGenCommand, TpmEcdhKeyGenResponse, EcdhKeyGen),
    (TpmFlushContextCommand, TpmFlushContextResponse, FlushContext),
    (TpmLoadExternalCommand, TpmLoadExternalResponse, LoadExternal),
    (TpmMakeCredentialCommand, TpmMakeCredentialResponse, MakeCredential),
    (TpmNvReadPublicCommand, TpmNvReadPublicResponse, NvReadPublic),
    (TpmPolicyAuthorizeCommand, TpmPolicyAuthorizeResponse, PolicyAuthorize),
    (TpmPolicyAuthValueCommand, TpmPolicyAuthValueResponse, PolicyAuthValue),
    (TpmPolicyCommandCodeCommand, TpmPolicyCommandCodeResponse, PolicyCommandCode),
    (TpmPolicyCounterTimerCommand, TpmPolicyCounterTimerResponse, PolicyCounterTimer),
    (TpmPolicyCpHashCommand, TpmPolicyCpHashResponse, PolicyCpHash),
    (TpmPolicyLocalityCommand, TpmPolicyLocalityResponse, PolicyLocality),
    (TpmPolicyNameHashCommand, TpmPolicyNameHashResponse, PolicyNameHash),
    (TpmPolicyOrCommand, TpmPolicyOrResponse, PolicyOr),
    (TpmPolicyTicketCommand, TpmPolicyTicketResponse, PolicyTicket),
    (TpmReadPublicCommand, TpmReadPublicResponse, ReadPublic),
    (TpmRsaEncryptCommand, TpmRsaEncryptResponse, RsaEncrypt),
    (TpmStartAuthSessionCommand, TpmStartAuthSessionResponse, StartAuthSession),
    (TpmVerifySignatureCommand, TpmVerifySignatureResponse, VerifySignature),
    (TpmEccParametersCommand, TpmEccParametersResponse, EccParameters),
    (TpmFirmwareReadCommand, TpmFirmwareReadResponse, FirmwareRead),
    (TpmGetCapabilityCommand, TpmGetCapabilityResponse, GetCapability),
    (TpmGetRandomCommand, TpmGetRandomResponse, GetRandom),
    (TpmGetTestResultCommand, TpmGetTestResultResponse, GetTestResult),
    (TpmHashCommand, TpmHashResponse, Hash),
    (TpmPcrReadCommand, TpmPcrReadResponse, PcrRead),
    (TpmPolicyPcrCommand, TpmPolicyPcrResponse, PolicyPcr),
    (TpmPolicyRestartCommand, TpmPolicyRestartResponse, PolicyRestart),
    (TpmReadClockCommand, TpmReadClockResponse, ReadClock),
    (TpmPcrExtendCommand, TpmPcrExtendResponse, PcrExtend),
    (TpmPcrSetAuthValueCommand, TpmPcrSetAuthValueResponse, PcrSetAuthValue),
    (TpmNvCertifyCommand, TpmNvCertifyResponse, NvCertify),
    (TpmEventSequenceCompleteCommand, TpmEventSequenceCompleteResponse, EventSequenceComplete),
    (TpmHashSequenceStartCommand, TpmHashSequenceStartResponse, HashSequenceStart),
    (TpmPolicyPhysicalPresenceCommand, TpmPolicyPhysicalPresenceResponse, PolicyPhysicalPresence),
    (TpmPolicyDuplicationSelectCommand, TpmPolicyDuplicationSelectResponse, PolicyDuplicationSelect),
    (TpmPolicyGetDigestCommand, TpmPolicyGetDigestResponse, PolicyGetDigest),
    (TpmPolicyPasswordCommand, TpmPolicyPasswordResponse, PolicyPassword),
    (TpmPolicyNvWrittenCommand, TpmPolicyNvWrittenResponse, PolicyNvWritten),
    (TpmPolicyTemplateCommand, TpmPolicyTemplateResponse, PolicyTemplate),
    (TpmPolicyAuthorizeNvCommand, TpmPolicyAuthorizeNvResponse, PolicyAuthorizeNv),
    (TpmEncryptDecrypt2Command, TpmEncryptDecrypt2Response, EncryptDecrypt2),
    (TpmAcGetCapabilityCommand, TpmAcGetCapabilityResponse, AcGetCapability),
    (TpmAcSendCommand, TpmAcSendResponse, AcSend),
    (TpmPolicyAcSendSelectCommand, TpmPolicyAcSendSelectResponse, PolicyAcSendSelect),
    (TpmActSetTimeoutCommand, TpmActSetTimeoutResponse, ActSetTimeout),
    (TpmPolicyCapabilityCommand, TpmPolicyCapabilityResponse, PolicyCapability),
    (TpmPolicyParametersCommand, TpmPolicyParametersResponse, PolicyParameters),
    (TpmNvDefineSpace2Command, TpmNvDefineSpace2Response, NvDefineSpace2),
    (TpmNvReadPublic2Command, TpmNvReadPublic2Response, NvReadPublic2),
    (TpmPolicyTransportSpdmCommand, TpmPolicyTransportSpdmResponse, PolicyTransportSpdm),
    (TpmVendorTcgTestCommand, TpmVendorTcgTestResponse, VendorTcgTest),
}
