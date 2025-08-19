// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{data, tpm_dispatch, TpmBuild, TpmList, TpmParse};
use core::fmt::Debug;

pub mod asymmetric;
pub mod attached;
pub mod attestation;
pub mod audit;
pub mod build;
pub mod capability;
pub mod clocks_and_timers;
pub mod context;
pub mod dictionary_attack;
pub mod duplication;
pub mod enhanced_authorization;
pub mod ephemeral;
pub mod field_upgrade;
pub mod hierarchy;
pub mod integrity;
pub mod miscellaneous_management;
pub mod non_volatile;
pub mod object;
pub mod parse;
pub mod random_number;
pub mod sequence;
pub mod session;
pub mod signing;
pub mod startup;
pub mod symmetric;
pub mod testing;
pub mod vendor;

pub use asymmetric::*;
pub use attached::*;
pub use attestation::*;
pub use audit::*;
pub use build::*;
pub use capability::*;
pub use clocks_and_timers::*;
pub use context::*;
pub use dictionary_attack::*;
pub use duplication::*;
pub use enhanced_authorization::*;
pub use ephemeral::*;
pub use field_upgrade::*;
pub use hierarchy::*;
pub use integrity::*;
pub use miscellaneous_management::*;
pub use non_volatile::*;
pub use object::*;
pub use parse::*;
pub use random_number::*;
pub use sequence::*;
pub use session::*;
pub use signing::*;
pub use startup::*;
pub use symmetric::*;
pub use testing::*;
pub use vendor::*;

/// The maximum number of handles a command can have.
pub const MAX_HANDLES: usize = 8;
/// The maximum number of sessions a command can have.
pub const MAX_SESSIONS: usize = 8;
/// A fixed-capacity list for TPM handles.
pub type TpmHandles = TpmList<u32, MAX_HANDLES>;
/// A fixed-capacity list for command authorization sessions.
pub type TpmAuthCommands = TpmList<data::TpmsAuthCommand, MAX_SESSIONS>;
/// A fixed-capacity list for response authorization sessions.
pub type TpmAuthResponses = TpmList<data::TpmsAuthResponse, MAX_SESSIONS>;
/// A trait for TPM commands and responses that provides header information.
pub trait TpmHeader: TpmBuild + TpmParse + Debug {
    const COMMAND: data::TpmCc;
    const NO_SESSIONS: bool;
    const WITH_SESSIONS: bool;
    const HANDLES: usize;
}

pub const TPM_HEADER_SIZE: usize = 10;

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
    (TpmPpCommandsCommand, TpmPpCommandsResponse, PpCommands),
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
    (TpmDictionaryAttackParametersCommand, TpmDictionaryAttackParametersResponse, DictionaryAttackParameters),
    (TpmNvChangeAuthCommand, TpmNvChangeAuthResponse, NvChangeAuth),
    (TpmPcrEventCommand, TpmPcrEventResponse, PcrEvent),
    (TpmPcrResetCommand, TpmPcrResetResponse, PcrReset),
    (TpmSequenceCompleteCommand, TpmSequenceCompleteResponse, SequenceComplete),
    (TpmSetAlgorithmSetCommand, TpmSetAlgorithmSetResponse, SetAlgorithmSet),
    (TpmSetCommandCodeAuditStatusCommand, TpmSetCommandCodeAuditStatusResponse, SetCommandCodeAuditStatus),
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
    (TpmHmacCommand, TpmHmacResponse, Hmac),
    (TpmImportCommand, TpmImportResponse, Import),
    (TpmLoadCommand, TpmLoadResponse, Load),
    (TpmQuoteCommand, TpmQuoteResponse, Quote),
    (TpmRsaDecryptCommand, TpmRsaDecryptResponse, RsaDecrypt),
    (TpmHmacStartCommand, TpmHmacStartResponse, HmacStart),
    (TpmSequenceUpdateCommand, TpmSequenceUpdateResponse, SequenceUpdate),
    (TpmSignCommand, TpmSignResponse, Sign),
    (TpmUnsealCommand, TpmUnsealResponse, Unseal),
    (TpmPolicySignedCommand, TpmPolicySignedResponse, PolicySigned),
    (TpmContextLoadCommand, TpmContextLoadResponse, ContextLoad),
    (TpmContextSaveCommand, TpmContextSaveResponse, ContextSave),
    (TpmEcdhKeyGenCommand, TpmEcdhKeyGenResponse, EcdhKeyGen),
    (TpmEncryptDecryptCommand, TpmEncryptDecryptResponse, EncryptDecrypt),
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
    (TpmTestParmsCommand, TpmTestParmsResponse, TestParms),
    (TpmCommitCommand, TpmCommitResponse, Commit),
    (TpmPolicyPasswordCommand, TpmPolicyPasswordResponse, PolicyPassword),
    (TpmZGen2PhaseCommand, TpmZGen2PhaseResponse, ZGen2Phase),
    (TpmEcEphemeralCommand, TpmEcEphemeralResponse, EcEphemeral),
    (TpmPolicyNvWrittenCommand, TpmPolicyNvWrittenResponse, PolicyNvWritten),
    (TpmPolicyTemplateCommand, TpmPolicyTemplateResponse, PolicyTemplate),
    (TpmCreateLoadedCommand, TpmCreateLoadedResponse, CreateLoaded),
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
    (TpmReadOnlyControlCommand, TpmReadOnlyControlResponse, ReadOnlyControl),
    (TpmPolicyTransportSpdmCommand, TpmPolicyTransportSpdmResponse, PolicyTransportSpdm),
    (TpmVendorTcgTestCommand, TpmVendorTcgTestResponse, VendorTcgTest),
}
