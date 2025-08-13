// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    tpm2b, tpm2b_struct, tpm_bitflags, tpm_bool, tpm_enum, tpm_hash_size, tpm_struct, tpml,
    TpmBuffer, TpmBuild, TpmErrorKind, TpmParse, TpmParseTagged, TpmResult, TpmSized, TpmTagged,
    TpmWriter, TPM_MAX_COMMAND_SIZE,
};
use core::{
    convert::TryFrom,
    fmt::{self, Debug, Display, Formatter},
    mem::size_of,
    ops::Deref,
};

pub const MAX_DIGEST_SIZE: usize = 64;
pub const MAX_ECC_KEY_BYTES: usize = 66;
pub const MAX_SYM_KEY_BYTES: usize = 32;
pub const MAX_LABEL_SIZE: usize = 32;
pub const MAX_RSA_KEY_BYTES: usize = 512;
pub const MAX_SENSITIVE_DATA: usize = 256;
pub const MAX_NV_BUFFER_SIZE: usize = 2048;
pub const MAX_TIMEOUT: usize = 8;
pub const MAX_CONTEXT_DATA: usize = 1664;
pub const MAX_DATA_SIZE: usize = 256;
pub const MAX_EVENT_SIZE: usize = 1024;
pub const MAX_BUFFER_SIZE: usize = 1024;
pub const MAX_OPERAND_SIZE: usize = 1024;
pub const MAX_PRIVATE_SIZE: usize = 1408;
pub const MAX_PRIVATE_VENDOR_SPECIFIC_SIZE: usize = 1024;

tpm2b!(Tpm2b, TPM_MAX_COMMAND_SIZE);
tpm2b!(Tpm2bAuth, MAX_DIGEST_SIZE);
tpm2b!(Tpm2bContextSensitive, MAX_CONTEXT_DATA);
tpm2b!(Tpm2bData, MAX_DATA_SIZE);
tpm2b!(Tpm2bDerive, MAX_DIGEST_SIZE);
tpm2b!(Tpm2bDigest, MAX_DIGEST_SIZE);
tpm2b!(Tpm2bEccParameter, MAX_ECC_KEY_BYTES);
tpm2b!(Tpm2bEncryptedSecret, MAX_ECC_KEY_BYTES);
tpm2b!(Tpm2bEvent, MAX_EVENT_SIZE);
tpm2b!(Tpm2bIv, MAX_SYM_KEY_BYTES);
tpm2b!(Tpm2bLabel, MAX_LABEL_SIZE);
tpm2b!(Tpm2bMaxBuffer, MAX_BUFFER_SIZE);
tpm2b!(Tpm2bMaxNvBuffer, MAX_NV_BUFFER_SIZE);
tpm2b!(Tpm2bName, { MAX_DIGEST_SIZE + 2 });
tpm2b!(Tpm2bNonce, MAX_DIGEST_SIZE);
tpm2b!(Tpm2bOperand, MAX_OPERAND_SIZE);
tpm2b!(Tpm2bPrivate, MAX_PRIVATE_SIZE);
tpm2b!(Tpm2bPrivateKeyRsa, MAX_RSA_KEY_BYTES);
tpm2b!(Tpm2bPrivateVendorSpecific, MAX_PRIVATE_VENDOR_SPECIFIC_SIZE);
tpm2b!(Tpm2bPublicKeyRsa, MAX_RSA_KEY_BYTES);
tpm2b!(Tpm2bSensitiveData, MAX_SENSITIVE_DATA);
tpm2b!(Tpm2bSymKey, MAX_SYM_KEY_BYTES);
tpm2b!(Tpm2bTimeout, MAX_TIMEOUT);

tpm_enum! {
    /// Enumeration of the `TPM_ALG_ID` values.
    ///
    /// Reference: TPM 2.0 Structures Specification, section 6.3.
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Default)]
    pub enum TpmAlgId(u16) {
        (Error, 0x0000, "TPM_ALG_ERROR"),
        (Rsa, 0x0001, "TPM_ALG_RSA"),
        (Sha1, 0x0004, "TPM_ALG_SHA1"),
        (Hmac, 0x0005, "TPM_ALG_HMAC"),
        (Aes, 0x0006, "TPM_ALG_AES"),
        (Mgf1, 0x0007, "TPM_ALG_MGF1"),
        (KeyedHash, 0x0008, "TPM_ALG_KEYEDHASH"),
        (Xor, 0x000A, "TPM_ALG_XOR"),
        (Sha256, 0x000B, "TPM_ALG_SHA256"),
        (Sha384, 0x000C, "TPM_ALG_SHA384"),
        (Sha512, 0x000D, "TPM_ALG_SHA512"),
        /// `TPM_ALG_NULL`
        #[default]
        (Null, 0x0010, "TPM_ALG_NULL"),
        (Sm3_256, 0x0012, "TPM_ALG_SM3_256"),
        (Sm4, 0x0013, "TPM_ALG_SM4"),
        (Rsassa, 0x0014, "TPM_ALG_RSASSA"),
        (Rsaes, 0x0015, "TPM_ALG_RSAES"),
        (Rsapss, 0x0016, "TPM_ALG_RSAPSS"),
        (Oaep, 0x0017, "TPM_ALG_OAEP"),
        (Ecdsa, 0x0018, "TPM_ALG_ECDSA"),
        (Ecdh, 0x0019, "TPM_ALG_ECDH"),
        (Ecdaa, 0x001A, "TPM_ALG_ECDAA"),
        (Sm2, 0x001B, "TPM_ALG_SM2"),
        (Ecschnorr, 0x001C, "TPM_ALG_ECSCHNORR"),
        (Ecmqv, 0x001D, "TPM_ALG_ECMQV"),
        (Kdf1Sp800_56A, 0x0020, "TPM_ALG_KDF1_SP800_56A"),
        (Kdf2, 0x0021, "TPM_ALG_KDF2"),
        (Kdf1Sp800_108, 0x0022, "TPM_ALG_KDF1_SP800_108"),
        (Ecc, 0x0023, "TPM_ALG_ECC"),
        (SymCipher, 0x0025, "TPM_ALG_SYMCIPHER"),
        (Camellia, 0x0026, "TPM_ALG_CAMELLIA"),
        (Ctr, 0x0040, "TPM_ALG_CTR"),
        (Ofb, 0x0041, "TPM_ALG_OFB"),
        (Cbc, 0x0042, "TPM_ALG_CBC"),
        (Cfb, 0x0043, "TPM_ALG_CFB"),
        (Ecb, 0x0044, "TPM_ALG_ECB"),
    }
}

tpm_enum! {
    /// `TPM_CAP`
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    pub enum TpmCap(u32) {
        (Algs, 0x0000_0000, "TPM_CAP_ALGS"),
        (Handles, 0x0000_0001, "TPM_CAP_HANDLES"),
        (Commands, 0x0000_0002, "TPM_CAP_COMMANDS"),
        (PpCommands, 0x0000_0003, "TPM_CAP_PP_COMMANDS"),
        (AuditCommands, 0x0000_0004, "TPM_CAP_AUDIT_COMMANDS"),
        (Pcrs, 0x0000_0005, "TPM_CAP_PCRS"),
        (TpmProperties, 0x0000_0006, "TPM_CAP_TPM_PROPERTIES"),
        (PcrProperties, 0x0000_0007, "TPM_CAP_PCR_PROPERTIES"),
        (EccCurves, 0x0000_0008, "TPM_CAP_ECC_CURVES"),
        (AuthPolicies, 0x0000_0009, "TPM_CAP_AUTH_POLICIES"),
    }
}

tpm_enum! {
    /// Enumeration of the `TPM_CC`values
    ///
    /// Reference: TPM 2.0 Structures Specification, section 6.5.2.
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
    pub enum TpmCc(u32) {
        (NvUndefineSpaceSpecial, 0x0000_011F, "TPM_CC_NV_UndefineSpaceSpecial"),
        (EvictControl, 0x0000_0120, "TPM_CC_EvictControl"),
        (HierarchyControl, 0x0000_0121, "TPM_CC_HierarchyControl"),
        (NvUndefineSpace, 0x0000_0122, "TPM_CC_NV_UndefineSpace"),
        (ChangeEps, 0x0000_0124, "TPM_CC_ChangeEPS"),
        (ChangePps, 0x0000_0125, "TPM_CC_ChangePPS"),
        (Clear, 0x0000_0126, "TPM_CC_Clear"),
        (ClearControl, 0x0000_0127, "TPM_CC_ClearControl"),
        (ClockSet, 0x0000_0128, "TPM_CC_ClockSet"),
        (HierarchyChangeAuth, 0x0000_0129, "TPM_CC_HierarchyChangeAuth"),
        (NvDefineSpace, 0x0000_012A, "TPM_CC_NV_DefineSpace"),
        (PcrAllocate, 0x0000_012B, "TPM_CC_PCR_Allocate"),
        (PcrSetAuthPolicy, 0x0000_012C, "TPM_CC_PCR_SetAuthPolicy"),
        (PpCommands, 0x0000_012D, "TPM_CC_PP_Commands"),
        (SetPrimaryPolicy, 0x0000_012E, "TPM_CC_SetPrimaryPolicy"),
        (FieldUpgradeStart, 0x0000_012F, "TPM_CC_FieldUpgradeStart"),
        (ClockRateAdjust, 0x0000_0130, "TPM_CC_ClockRateAdjust"),
        (CreatePrimary, 0x0000_0131, "TPM_CC_CreatePrimary"),
        (NvGlobalWriteLock, 0x0000_0132, "TPM_CC_NV_GlobalWriteLock"),
        (GetCommandAuditDigest, 0x0000_0133, "TPM_CC_GetCommandAuditDigest"),
        (NvIncrement, 0x0000_0134, "TPM_CC_NV_Increment"),
        (NvSetBits, 0x0000_0135, "TPM_CC_NV_SetBits"),
        (NvExtend, 0x0000_0136, "TPM_CC_NV_Extend"),
        (NvWrite, 0x0000_0137, "TPM_CC_NV_Write"),
        (NvWriteLock, 0x0000_0138, "TPM_CC_NV_WriteLock"),
        (DictionaryAttackLockReset, 0x0000_0139, "TPM_CC_DictionaryAttackLockReset"),
        (DictionaryAttackParameters, 0x0000_013A, "TPM_CC_DictionaryAttackParameters"),
        (NvChangeAuth, 0x0000_013B, "TPM_CC_NV_ChangeAuth"),
        (PcrEvent, 0x0000_013C, "TPM_CC_PCR_Event"),
        (PcrReset, 0x0000_013D, "TPM_CC_PCR_Reset"),
        (SequenceComplete, 0x0000_013E, "TPM_CC_SequenceComplete"),
        (SetAlgorithmSet, 0x0000_013F, "TPM_CC_SetAlgorithmSet"),
        (SetCommandCodeAuditStatus, 0x0000_0140, "TPM_CC_SetCommandCodeAuditStatus"),
        (FieldUpgradeData, 0x0000_0141, "TPM_CC_FieldUpgradeData"),
        (IncrementalSelfTest, 0x0000_0142, "TPM_CC_IncrementalSelfTest"),
        (SelfTest, 0x0000_0143, "TPM_CC_SelfTest"),
        (Startup, 0x0000_0144, "TPM_CC_Startup"),
        (Shutdown, 0x0000_0145, "TPM_CC_Shutdown"),
        (StirRandom, 0x0000_0146, "TPM_CC_StirRandom"),
        (ActivateCredential, 0x0000_0147, "TPM_CC_ActivateCredential"),
        (Certify, 0x0000_0148, "TPM_CC_Certify"),
        (PolicyNv, 0x0000_0149, "TPM_CC_PolicyNV"),
        (CertifyCreation, 0x0000_014A, "TPM_CC_CertifyCreation"),
        (Duplicate, 0x0000_014B, "TPM_CC_Duplicate"),
        (GetTime, 0x0000_014C, "TPM_CC_GetTime"),
        (GetSessionAuditDigest, 0x0000_014D, "TPM_CC_GetSessionAuditDigest"),
        (NvRead, 0x0000_014E, "TPM_CC_NV_Read"),
        (NvReadLock, 0x0000_014F, "TPM_CC_NV_ReadLock"),
        (ObjectChangeAuth, 0x0000_0150, "TPM_CC_ObjectChangeAuth"),
        (PolicySecret, 0x0000_0151, "TPM_CC_PolicySecret"),
        (Rewrap, 0x0000_0152, "TPM_CC_Rewrap"),
        (Create, 0x0000_0153, "TPM_CC_Create"),
        (EcdhZGen, 0x0000_0154, "TPM_CC_ECDH_ZGen"),
        (Hmac, 0x0000_0155, "TPM_CC_HMAC"),
        (Import, 0x0000_0156, "TPM_CC_Import"),
        (Load, 0x0000_0157, "TPM_CC_Load"),
        (Quote, 0x0000_0158, "TPM_CC_Quote"),
        (RsaDecrypt, 0x0000_0159, "TPM_CC_RSA_Decrypt"),
        (HmacStart, 0x0000_015B, "TPM_CC_HMAC_Start"),
        (SequenceUpdate, 0x0000_015C, "TPM_CC_SequenceUpdate"),
        (Sign, 0x0000_015D, "TPM_CC_Sign"),
        (Unseal, 0x0000_015E, "TPM_CC_Unseal"),
        (PolicySigned, 0x0000_0160, "TPM_CC_PolicySigned"),
        (ContextLoad, 0x0000_0161, "TPM_CC_ContextLoad"),
        (ContextSave, 0x0000_0162, "TPM_CC_ContextSave"),
        (EcdhKeygen, 0x0000_0163, "TPM_CC_ECDH_KeyGen"),
        (EncryptDecrypt, 0x0000_0164, "TPM_CC_EncryptDecrypt"),
        (FlushContext, 0x0000_0165, "TPM_CC_FlushContext"),
        (LoadExternal, 0x0000_0167, "TPM_CC_LoadExternal"),
        (MakeCredential, 0x0000_0168, "TPM_CC_MakeCredential"),
        (NvReadPublic, 0x0000_0169, "TPM_CC_NV_ReadPublic"),
        (PolicyAuthorize, 0x0000_016A, "TPM_CC_PolicyAuthorize"),
        (PolicyAuthValue, 0x0000_016B, "TPM_CC_PolicyAuthValue"),
        (PolicyCommandCode, 0x0000_016C, "TPM_CC_PolicyCommandCode"),
        (PolicyCounterTimer, 0x0000_016D, "TPM_CC_PolicyCounterTimer"),
        (PolicyCpHash, 0x0000_016E, "TPM_CC_PolicyCpHash"),
        (PolicyLocality, 0x0000_016F, "TPM_CC_PolicyLocality"),
        (PolicyNameHash, 0x0000_0170, "TPM_CC_PolicyNameHash"),
        (PolicyOR, 0x0000_0171, "TPM_CC_PolicyOR"),
        (PolicyTicket, 0x0000_0172, "TPM_CC_PolicyTicket"),
        (ReadPublic, 0x0000_0173, "TPM_CC_ReadPublic"),
        (RsaEncrypt, 0x0000_0174, "TPM_CC_RSA_Encrypt"),
        (StartAuthSession, 0x0000_0176, "TPM_CC_StartAuthSession"),
        (VerifySignature, 0x0000_0177, "TPM_CC_VerifySignature"),
        (EccParameters, 0x0000_0178, "TPM_CC_ECC_Parameters"),
        (FirmwareRead, 0x0000_0179, "TPM_CC_FirmwareRead"),
        (GetCapability, 0x0000_017A, "TPM_CC_GetCapability"),
        (GetRandom, 0x0000_017B, "TPM_CC_GetRandom"),
        (GetTestResult, 0x0000_017C, "TPM_CC_GetTestResult"),
        (Hash, 0x0000_017D, "TPM_CC_Hash"),
        (PcrRead, 0x0000_017E, "TPM_CC_PCR_Read"),
        (PolicyPcr, 0x0000_017F, "TPM_CC_PolicyPCR"),
        (PolicyRestart, 0x0000_0180, "TPM_CC_PolicyRestart"),
        (ReadClock, 0x0000_0181, "TPM_CC_ReadClock"),
        (PcrExtend, 0x0000_0182, "TPM_CC_PCR_Extend"),
        (PcrSetAuthValue, 0x0000_0183, "TPM_CC_PCR_SetAuthValue"),
        (NvCertify, 0x0000_0184, "TPM_CC_NV_Certify"),
        (EventSequenceComplete, 0x0000_0185, "TPM_CC_EventSequenceComplete"),
        (HashSequenceStart, 0x0000_0186, "TPM_CC_HashSequenceStart"),
        (PolicyPhysicalPresence, 0x0000_0187, "TPM_CC_PolicyPhysicalPresence"),
        (PolicyDuplicationSelect, 0x0000_0188, "TPM_CC_PolicyDuplicationSelect"),
        (PolicyGetDigest, 0x0000_0189, "TPM_CC_PolicyGetDigest"),
        (TestParms, 0x0000_018A, "TPM_CC_TestParms"),
        (Commit, 0x0000_018B, "TPM_CC_Commit"),
        (PolicyPassword, 0x0000_018C, "TPM_CC_PolicyPassword"),
        (ZGen2Phase, 0x0000_018D, "TPM_CC_ZGen_2Phase"),
        (EcEphemeral, 0x0000_018E, "TPM_CC_EC_Ephemeral"),
        (PolicyNvWritten, 0x0000_018F, "TPM_CC_PolicyNvWritten"),
        (PolicyTemplate, 0x0000_0190, "TPM_CC_PolicyTemplate"),
        (CreateLoaded, 0x0000_0191, "TPM_CC_CreateLoaded"),
        (PolicyAuthorizeNv, 0x0000_0192, "TPM_CC_PolicyAuthorizeNV"),
        (EncryptDecrypt2, 0x0000_0193, "TPM_CC_EncryptDecrypt2"),
        (VendorTcgTest, 0x2000_0000, "TPM_CC_Vendor_TCG_Test"),
    }
}

tpm_enum! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum TpmEccCurve(u16) {
        (None, 0x0000, "TPM_ECC_NONE"),
        (NistP192, 0x0001, "TPM_ECC_NIST_P192"),
        (NistP224, 0x0002, "TPM_ECC_NIST_P224"),
        (NistP256, 0x0003, "TPM_ECC_NIST_P256"),
        (NistP384, 0x0004, "TPM_ECC_NIST_P384"),
        (NistP521, 0x0005, "TPM_ECC_NIST_P521"),
    }
}

pub const TPM_RC_VER1: u32 = 0x0100;
pub const TPM_RC_FMT1: u32 = 0x0080;
pub const TPM_RC_WARN: u32 = 0x0900;
pub const TPM_RC_P_BIT: u32 = 1 << 6;
pub const TPM_RC_N_SHIFT: u32 = 8;
pub const TPM_RC_FMT1_ERROR_MASK: u32 = 0x003F;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TpmRcIndex {
    Parameter(u8),
    Handle(u8),
    Session(u8),
}

impl Display for TpmRcIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TpmRcIndex::Parameter(i) => write!(f, "parameter[{i}]"),
            TpmRcIndex::Handle(i) => write!(f, "handle[{i}]"),
            TpmRcIndex::Session(i) => write!(f, "session[{i}]"),
        }
    }
}

fn tpm_parse_base(value: u32) -> Result<TpmRcBase, crate::TpmErrorKind> {
    let base_code = if (value & TPM_RC_FMT1) != 0 {
        TPM_RC_FMT1 | (value & TPM_RC_FMT1_ERROR_MASK)
    } else {
        value
    };
    TpmRcBase::try_from(base_code).map_err(|()| crate::TpmErrorKind::InvalidDiscriminant {
        type_name: "TpmRcBase",
        value: u64::from(base_code),
    })
}

tpm_enum! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    #[allow(clippy::upper_case_acronyms)]
    pub enum TpmRcBase(u32) {
        (Success, 0x0000, "TPM_RC_SUCCESS"),
        (BadTag, 0x001E, "TPM_RC_BAD_TAG"),
        (Initialize, TPM_RC_VER1, "TPM_RC_INITIALIZE"),
        (Failure, TPM_RC_VER1 | 0x001, "TPM_RC_FAILURE"),
        (Sequence, TPM_RC_VER1 | 0x003, "TPM_RC_SEQUENCE"),
        (Private, TPM_RC_VER1 | 0x00B, "TPM_RC_PRIVATE"),
        (Hmac, TPM_RC_VER1 | 0x019, "TPM_RC_HMAC"),
        (Disabled, TPM_RC_VER1 | 0x020, "TPM_RC_DISABLED"),
        (Exclusive, TPM_RC_VER1 | 0x021, "TPM_RC_EXCLUSIVE"),
        (AuthType, TPM_RC_VER1 | 0x024, "TPM_RC_AUTH_TYPE"),
        (AuthMissing, TPM_RC_VER1 | 0x025, "TPM_RC_AUTH_MISSING"),
        (Policy, TPM_RC_VER1 | 0x026, "TPM_RC_POLICY"),
        (Pcr, TPM_RC_VER1 | 0x027, "TPM_RC_PCR"),
        (PcrChanged, TPM_RC_VER1 | 0x028, "TPM_RC_PCR_CHANGED"),
        (Upgrade, TPM_RC_VER1 | 0x02D, "TPM_RC_UPGRADE"),
        (TooManyContexts, TPM_RC_VER1 | 0x02E, "TPM_RC_TOO_MANY_CONTEXTS"),
        (AuthUnavailable, TPM_RC_VER1 | 0x02F, "TPM_RC_AUTH_UNAVAILABLE"),
        (Reboot, TPM_RC_VER1 | 0x030, "TPM_RC_REBOOT"),
        (Unbalanced, TPM_RC_VER1 | 0x031, "TPM_RC_UNBALANCED"),
        (CommandSize, TPM_RC_VER1 | 0x042, "TPM_RC_COMMAND_SIZE"),
        (CommandCode, TPM_RC_VER1 | 0x043, "TPM_RC_COMMAND_CODE"),
        (AuthSize, TPM_RC_VER1 | 0x044, "TPM_RC_AUTHSIZE"),
        (AuthContext, TPM_RC_VER1 | 0x045, "TPM_RC_AUTH_CONTEXT"),
        (NvRange, TPM_RC_VER1 | 0x046, "TPM_RC_NV_RANGE"),
        (NvSize, TPM_RC_VER1 | 0x047, "TPM_RC_NV_SIZE"),
        (NvLocked, TPM_RC_VER1 | 0x048, "TPM_RC_NV_LOCKED"),
        (NvAuthorization, TPM_RC_VER1 | 0x049, "TPM_RC_NV_AUTHORIZATION"),
        (NvUninitialized, TPM_RC_VER1 | 0x04A, "TPM_RC_NV_UNINITIALIZED"),
        (NvSpace, TPM_RC_VER1 | 0x04B, "TPM_RC_NV_SPACE"),
        (NvDefined, TPM_RC_VER1 | 0x04C, "TPM_RC_NV_DEFINED"),
        (BadContext, TPM_RC_VER1 | 0x050, "TPM_RC_BAD_CONTEXT"),
        (CpHash, TPM_RC_VER1 | 0x051, "TPM_RC_CPHASH"),
        (Parent, TPM_RC_VER1 | 0x052, "TPM_RC_PARENT"),
        (NeedsTest, TPM_RC_VER1 | 0x053, "TPM_RC_NEEDS_TEST"),
        (NoResult, TPM_RC_VER1 | 0x054, "TPM_RC_NO_RESULT"),
        (Sensitive, TPM_RC_VER1 | 0x055, "TPM_RC_SENSITIVE"),
        (ReadOnly, TPM_RC_VER1 | 0x056, "TPM_RC_READ_ONLY"),
        (Asymmetric, TPM_RC_FMT1 | 0x001, "TPM_RC_ASYMMETRIC"),
        (Attributes, TPM_RC_FMT1 | 0x002, "TPM_RC_ATTRIBUTES"),
        (Hash, TPM_RC_FMT1 | 0x003, "TPM_RC_HASH"),
        (Value, TPM_RC_FMT1 | 0x004, "TPM_RC_VALUE"),
        (Hierarchy, TPM_RC_FMT1 | 0x005, "TPM_RC_HIERARCHY"),
        (KeySize, TPM_RC_FMT1 | 0x007, "TPM_RC_KEY_SIZE"),
        (Mgf, TPM_RC_FMT1 | 0x008, "TPM_RC_MGF"),
        (Mode, TPM_RC_FMT1 | 0x009, "TPM_RC_MODE"),
        (Type, TPM_RC_FMT1 | 0x00A, "TPM_RC_TYPE"),
        (Handle, TPM_RC_FMT1 | 0x00B, "TPM_RC_HANDLE"),
        (Kdf, TPM_RC_FMT1 | 0x00C, "TPM_RC_KDF"),
        (Range, TPM_RC_FMT1 | 0x00D, "TPM_RC_RANGE"),
        (AuthFail, TPM_RC_FMT1 | 0x00E, "TPM_RC_AUTH_FAIL"),
        (Nonce, TPM_RC_FMT1 | 0x00F, "TPM_RC_NONCE"),
        (Pp, TPM_RC_FMT1 | 0x010, "TPM_RC_PP"),
        (Scheme, TPM_RC_FMT1 | 0x012, "TPM_RC_SCHEME"),
        (Size, TPM_RC_FMT1 | 0x015, "TPM_RC_SIZE"),
        (Symmetric, TPM_RC_FMT1 | 0x016, "TPM_RC_SYMMETRIC"),
        (Tag, TPM_RC_FMT1 | 0x017, "TPM_RC_TAG"),
        (Selector, TPM_RC_FMT1 | 0x018, "TPM_RC_SELECTOR"),
        (Insufficient, TPM_RC_FMT1 | 0x01A, "TPM_RC_INSUFFICIENT"),
        (Signature, TPM_RC_FMT1 | 0x01B, "TPM_RC_SIGNATURE"),
        (Key, TPM_RC_FMT1 | 0x01C, "TPM_RC_KEY"),
        (PolicyFail, TPM_RC_FMT1 | 0x01D, "TPM_RC_POLICY_FAIL"),
        (Integrity, TPM_RC_FMT1 | 0x01F, "TPM_RC_INTEGRITY"),
        (Ticket, TPM_RC_FMT1 | 0x020, "TPM_RC_TICKET"),
        (ReservedBits, TPM_RC_FMT1 | 0x021, "TPM_RC_RESERVED_BITS"),
        (BadAuth, TPM_RC_FMT1 | 0x022, "TPM_RC_BAD_AUTH"),
        (Expired, TPM_RC_FMT1 | 0x023, "TPM_RC_EXPIRED"),
        (PolicyCc, TPM_RC_FMT1 | 0x024, "TPM_RC_POLICY_CC"),
        (Binding, TPM_RC_FMT1 | 0x025, "TPM_RC_BINDING"),
        (Curve, TPM_RC_FMT1 | 0x026, "TPM_RC_CURVE"),
        (EccPoint, TPM_RC_FMT1 | 0x027, "TPM_RC_ECC_POINT"),
        (FwLimited, TPM_RC_FMT1 | 0x028, "TPM_RC_FW_LIMITED"),
        (SvnLimited, TPM_RC_FMT1 | 0x029, "TPM_RC_SVN_LIMITED"),
        (Channel, TPM_RC_FMT1 | 0x030, "TPM_RC_CHANNEL"),
        (ChannelKey, TPM_RC_FMT1 | 0x031, "TPM_RC_CHANNEL_KEY"),
        (ContextGap, TPM_RC_WARN | 0x001, "TPM_RC_CONTEXT_GAP"),
        (ObjectMemory, TPM_RC_WARN | 0x002, "TPM_RC_OBJECT_MEMORY"),
        (SessionMemory, TPM_RC_WARN | 0x003, "TPM_RC_SESSION_MEMORY"),
        (Memory, TPM_RC_WARN | 0x004, "TPM_RC_MEMORY"),
        (TpmSessions, TPM_RC_WARN | 0x005, "TPM_RC_SESSION_HANDLES"),
        (TpmTransients, TPM_RC_WARN | 0x006, "TPM_RC_OBJECT_HANDLES"),
        (Locality, TPM_RC_WARN | 0x007, "TPM_RC_LOCALITY"),
        (Yielded, TPM_RC_WARN | 0x008, "TPM_RC_YIELDED"),
        (Canceled, TPM_RC_WARN | 0x009, "TPM_RC_CANCELED"),
        (Testing, TPM_RC_WARN | 0x00A, "TPM_RC_TESTING"),
        (ReferenceH0, TPM_RC_WARN | 0x010, "TPM_RC_REFERENCE_H0"),
        (ReferenceH1, TPM_RC_WARN | 0x011, "TPM_RC_REFERENCE_H1"),
        (ReferenceH2, TPM_RC_WARN | 0x012, "TPM_RC_REFERENCE_H2"),
        (ReferenceH3, TPM_RC_WARN | 0x013, "TPM_RC_REFERENCE_H3"),
        (ReferenceH4, TPM_RC_WARN | 0x014, "TPM_RC_REFERENCE_H4"),
        (ReferenceH5, TPM_RC_WARN | 0x015, "TPM_RC_REFERENCE_H5"),
        (ReferenceH6, TPM_RC_WARN | 0x016, "TPM_RC_REFERENCE_H6"),
        (ReferenceS0, TPM_RC_WARN | 0x018, "TPM_RC_REFERENCE_S0"),
        (ReferenceS1, TPM_RC_WARN | 0x019, "TPM_RC_REFERENCE_S1"),
        (ReferenceS2, TPM_RC_WARN | 0x01A, "TPM_RC_REFERENCE_S2"),
        (ReferenceS3, TPM_RC_WARN | 0x01B, "TPM_RC_REFERENCE_S3"),
        (ReferenceS4, TPM_RC_WARN | 0x01C, "TPM_RC_REFERENCE_S4"),
        (ReferenceS5, TPM_RC_WARN | 0x01D, "TPM_RC_REFERENCE_S5"),
        (ReferenceS6, TPM_RC_WARN | 0x01E, "TPM_RC_REFERENCE_S6"),
        (NvRate, TPM_RC_WARN | 0x020, "TPM_RC_NV_RATE"),
        (Lockout, TPM_RC_WARN | 0x021, "TPM_RC_LOCKOUT"),
        (Retry, TPM_RC_WARN | 0x022, "TPM_RC_RETRY"),
        (NvUnavailable, TPM_RC_WARN | 0x023, "TPM_RC_NV_UNAVAILABLE"),
        (NotUsed, 0xFFFF_FFFF, "TPM_RC_NOT_USED"),
    }
}

#[must_use]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct TpmRc(u32);

impl TpmRc {
    /// Returns the base of the response code.
    ///
    /// # Errors
    ///
    /// Returns `TpmErrorKind::InvalidDiscriminant` if the base of the response
    /// code is not a recognized `TpmRcBase` variant.
    pub fn base(self) -> Result<TpmRcBase, crate::TpmErrorKind> {
        tpm_parse_base(self.0)
    }

    /// Returns the index of a parameter, handle, or session in error for format 1 response codes.
    #[must_use]
    pub fn index(self) -> Option<TpmRcIndex> {
        let value = self.0;

        if (value & TPM_RC_FMT1) == 0 {
            return None;
        }

        let is_parameter = (value & TPM_RC_P_BIT) != 0;

        let n = ((value >> TPM_RC_N_SHIFT) & 0b1111) as u8;
        if n == 0 {
            return None;
        }

        if is_parameter {
            Some(TpmRcIndex::Parameter(n))
        } else if n <= 7 {
            Some(TpmRcIndex::Handle(n))
        } else {
            Some(TpmRcIndex::Session(n - 7))
        }
    }

    /// Returns the raw `u32` value of the response code.
    #[must_use]
    pub fn value(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for TpmRc {
    type Error = crate::TpmErrorKind;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        tpm_parse_base(value)?;
        Ok(TpmRc(value))
    }
}

impl From<TpmRc> for u32 {
    fn from(val: TpmRc) -> Self {
        val.0
    }
}

impl From<TpmRcBase> for TpmRc {
    fn from(value: TpmRcBase) -> Self {
        TpmRc(value as u32)
    }
}

impl Display for TpmRc {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.base() {
            Ok(base) => {
                if let Some(index) = self.index() {
                    write!(f, "[{base}, {index}]")
                } else {
                    write!(f, "{base}")
                }
            }
            Err(_) => {
                write!(f, "TPM_RC_UNKNOWN(0x{:08X})", self.0)
            }
        }
    }
}

tpm_enum! {
    /// `TPM_RH`
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    pub enum TpmRh(u32) {
        (Srk, 0x4000_0000, "TPM_RH_SRK"),
        (Owner, 0x4000_0001, "TPM_RH_OWNER"),
        #[default]
        (Null, 0x4000_0007, "TPM_RH_NULL"),
        (Unassigned, 0x4000_0008, "TPM_RH_UNASSIGNED"),
        (Password, 0x4000_0009, "TPM_RH_PW"),
        (Lockout, 0x4000_000A, "TPM_RH_LOCKOUT"),
        (Endorsement, 0x4000_000B, "TPM_RH_ENDORSEMENT"),
        (Platform, 0x4000_000C, "TPM_RH_PLATFORM"),
        (PlatformNv, 0x4000_000D, "TPM_RH_PLATFORM_NV"),
        (Auth00, 0x4000_0010, "TPM_RH_AUTH_00"),
        (AuthFF, 0x4000_010F, "TPM_RH_AUTH_FF"),
        (TransientFirst, 0x8000_0000, "First transient handle"),
        (PersistentFirst, 0x8100_0000, "First persistent handle"),
    }
}

tpm_enum! {
    /// `TPM_SE`
    #[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
    pub enum TpmSe(u8) {
        /// `TPM_SE_HMAC`
        #[default]
        (Hmac, 0x00, "TPM_SE_HMAC"),
        /// `TPM_SE_POLICY`
        (Policy, 0x01, "TPM_SE_POLICY"),
        /// `TPM_SE_TRIAL`
        (Trial, 0x03, "TPM_SE_TRIAL"),
    }
}

tpm_enum! {
    /// `TPM_ST`
    #[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
    pub enum TpmSt(u16) {
        (RspCommand, 0x00C4, "TPM_ST_RSP_COMMAND"),
        #[default]
        (Null, 0x8000, "TPM_ST_NULL"),
        (NoSessions, 0x8001, "TPM_ST_NO_SESSIONS"),
        (Sessions, 0x8002, "TPM_ST_SESSIONS"),
        (AttestNv, 0x8014, "TPM_ST_ATTEST_NV"),
        (AttestCommandAudit, 0x8015, "TPM_ST_ATTEST_COMMAND_AUDIT"),
        (AttestSessionAudit, 0x8016, "TPM_ST_ATTEST_SESSION_AUDIT"),
        (AttestCertify, 0x8017, "TPM_ST_ATTEST_CERTIFY"),
        (AttestQuote, 0x8018, "TPM_ST_ATTEST_QUOTE"),
        (AttestTime, 0x8019, "TPM_ST_ATTEST_TIME"),
        (AttestCreation, 0x801A, "TPM_ST_ATTEST_CREATION"),
        (Creation, 0x8021, "TPM_ST_CREATION"),
        (Verified, 0x8022, "TPM_ST_VERIFIED"),
        (AuthSecret, 0x8023, "TPM_ST_AUTH_SECRET"),
        (HashCheck, 0x8024, "TPM_ST_HASHCHECK"),
        (AuthSigned, 0x8025, "TPM_ST_AUTH_SIGNED"),
        (FuManifest, 0x8029, "TPM_ST_FU_MANIFEST"),
    }
}

tpm_bitflags! {
    /// `TPMA_ALGORITHM`
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TpmaAlgorithm(u32) {
        /// `TPMA_ALGORITHM_ASYMMETRIC`
        const ASYMMETRIC = 0x0000_0001;
        /// `TPMA_ALGORITHM_SYMMETRIC`
        const SYMMETRIC = 0x0000_0002;
        /// `TPMA_ALGORITHM_HASH`
        const HASH = 0x0000_0004;
        /// `TPMA_ALGORITHM_OBJECT`
        const OBJECT = 0x0000_0008;
        /// `TPMA_ALGORITHM_SIGNING`
        const SIGNING = 0x0000_0100;
        /// `TPMA_ALGORITHM_ENCRYPTING`
        const ENCRYPTING = 0x0000_0200;
        /// `TPMA_ALGORITHM_METHOD`
        const METHOD = 0x0000_0400;
        /// `TPMA_ALGORITHM_RSA_KEY_SIZES_1024`
        const RSA_KEY_SIZES_1024 = 0x0001_0000;
        /// `TPMA_ALGORITHM_RSA_KEY_SIZES_2048`
        const RSA_KEY_SIZES_2048 = 0x0002_0000;
        /// `TPMA_ALGORITHM_RSA_KEY_SIZES_3072`
        const RSA_KEY_SIZES_3072 = 0x0004_0000;
        /// `TPMA_ALGORITHM_RSA_KEY_SIZES_4096`
        const RSA_KEY_SIZES_4096 = 0x0008_0000;
    }
}

tpm_bitflags! {
    /// `TPMA_LOCALITY` (Table 41)
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TpmaLocality(u8) {
        const TPM_LOC_ZERO = 0x01;
        const TPM_LOC_ONE = 0x02;
        const TPM_LOC_TWO = 0x04;
        const TPM_LOC_THREE = 0x08;
        const TPM_LOC_FOUR = 0x10;
        const EXTENDED = 0xE0;
    }
}

tpm_bitflags! {
    /// `TPMA_NV` (Table 233)
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TpmaNv(u32) {
        const PPWRITE = 0x0000_0001;
        const OWNERWRITE = 0x0000_0002;
        const AUTHWRITE = 0x0000_0004;
        const POLICYWRITE = 0x0000_0008;
        const TPM_NT_ORDINARY = 0x0000_0000;
        const TPM_NT_COUNTER = 0x0000_0010;
        const TPM_NT_BITS = 0x0000_0020;
        const TPM_NT_EXTEND = 0x0000_0040;
        const TPM_NT_PIN_FAIL = 0x0000_0080;
        const TPM_NT_PIN_PASS = 0x0000_0090;
        const POLICY_DELETE = 0x0000_0400;
        const WRITELOCKED = 0x0000_0800;
        const WRITEALL = 0x0000_1000;
        const WRITEDEFINE = 0x0000_2000;
        const WRITE_STCLEAR = 0x0000_4000;
        const GLOBALLOCK = 0x0000_8000;
        const PPREAD = 0x0001_0000;
        const OWNERREAD = 0x0002_0000;
        const AUTHREAD = 0x0004_0000;
        const POLICYREAD = 0x0008_0000;
        const NO_DA = 0x0200_0000;
        const ORDERLY = 0x0400_0000;
        const CLEAR_STCLEAR = 0x0800_0000;
        const READLOCKED = 0x1000_0000;
        const WRITTEN = 0x2000_0000;
        const PLATFORMCREATE = 0x4000_0000;
        const READ_STCLEAR = 0x8000_0000;
    }
}

tpm_bitflags! {
    /// `TPMA_OBJECT`
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TpmaObject(u32) {
        /// Hierarchy is immutable
        const FIXED_TPM = 0x0000_0002;
        /// TPM chip reset invalidates also saved contexts
        const ST_CLEAR = 0x0000_0004;
        /// Parent is immutable
        const FIXED_PARENT = 0x0000_0010;
        /// TPM-only generated secrets
        const SENSITIVE_DATA_ORIGIN = 0x0000_0020;
        /// Allow user access without policy session
        const USER_WITH_AUTH = 0x0000_0040;
        /// Deny admin access without policy session
        const ADMIN_WITH_POLICY = 0x0000_0080;
        /// Deny dictionary attack protections
        const NO_DA = 0x0000_0400;
        /// Encrypted duplication
        const ENCRYPTED_DUPLICATION = 0x0000_0800;
        /// Manipulate only datas of known format
        const RESTRICTED = 0x0001_0000;
        /// Decrypt with the private key
        const DECRYPT = 0x0002_0000;
        /// Sign with the private key (for asymmetric keys) or encrypt (for symmetric keys)
        const SIGN_ENCRYPT = 0x0004_0000;
    }
}

tpm_bitflags! {
    /// `TPMA_SESSION`
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TpmaSession(u8) {
        const CONTINUE_SESSION = 0x01;
        const AUDIT_EXCLUSIVE = 0x02;
        const AUDIT_RESET = 0x04;
        const DECRYPT = 0x20;
        const ENCRYPT = 0x40;
        const AUDIT = 0x80;
    }
}

tpm_bool! {
    /// A TPM boolean value, corresponding to `TPMI_YES_NO`.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct TpmiYesNo(bool);
}

tpml!(TpmlAlgProperty, TpmsAlgProperty, 64);
tpml!(TpmlDigest, Tpm2bDigest, 8);
tpml!(TpmlDigestValues, TpmtHa, 8);
tpml!(TpmlHandle, u32, 128);
tpml!(TpmlPcrSelection, TpmsPcrSelection, 8);

pub const TPM_ST_GENERATED_VALUE: u32 = 0xFF54_4347;
pub const TPM_PCR_SELECT_MAX: usize = 3;

pub type TpmsPcrSelect = TpmBuffer<TPM_PCR_SELECT_MAX>;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsAlgProperty {
        pub alg: TpmAlgId,
        pub alg_properties: TpmaAlgorithm,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TpmsAttest {
    pub tag: TpmSt,
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub attested: TpmuAttest,
}

impl TpmTagged for TpmsAttest {
    type Tag = TpmSt;
    type Value = TpmuAttest;
}

impl TpmSized for TpmsAttest {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        size_of::<u32>()
            + self.tag.len()
            + self.qualified_signer.len()
            + self.extra_data.len()
            + self.clock_info.len()
            + self.firmware_version.len()
            + self.attested.len()
    }
}

impl TpmBuild for TpmsAttest {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        TPM_ST_GENERATED_VALUE.build(writer)?;
        self.tag.build(writer)?;
        self.qualified_signer.build(writer)?;
        self.extra_data.build(writer)?;
        self.clock_info.build(writer)?;
        self.firmware_version.build(writer)?;
        self.attested.build(writer)
    }
}

impl<'a> TpmParse<'a> for TpmsAttest {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (magic, buf) = u32::parse(buf)?;
        if magic != TPM_ST_GENERATED_VALUE {
            return Err(TpmErrorKind::InvalidMagic {
                expected: TPM_ST_GENERATED_VALUE,
                got: magic,
            });
        }

        let (tag, buf) = TpmSt::parse(buf)?;
        let (qualified_signer, buf) = Tpm2bName::parse(buf)?;
        let (extra_data, buf) = Tpm2bData::parse(buf)?;
        let (clock_info, buf) = TpmsClockInfo::parse(buf)?;
        let (firmware_version, buf) = u64::parse(buf)?;
        let (attested, buf) = TpmuAttest::parse_tagged(tag, buf)?;

        Ok((
            Self {
                tag,
                qualified_signer,
                extra_data,
                clock_info,
                firmware_version,
                attested,
            },
            buf,
        ))
    }
}

impl Default for TpmsAttest {
    fn default() -> Self {
        Self {
            tag: TpmSt::AttestQuote,
            qualified_signer: Tpm2bName::default(),
            extra_data: Tpm2bData::default(),
            clock_info: TpmsClockInfo::default(),
            firmware_version: 0,
            attested: TpmuAttest::default(),
        }
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsAuthCommand {
        pub session_handle: crate::TpmSession,
        pub nonce: Tpm2bNonce,
        pub session_attributes: TpmaSession,
        pub hmac: Tpm2bAuth,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsAuthResponse {
        pub nonce: Tpm2bNonce,
        pub session_attributes: TpmaSession,
        pub hmac: Tpm2bAuth,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TpmsCapabilityData {
    pub capability: TpmCap,
    pub data: TpmuCapabilities,
}

impl TpmTagged for TpmsCapabilityData {
    type Tag = TpmCap;
    type Value = ();
}

impl TpmSized for TpmsCapabilityData {
    const SIZE: usize = size_of::<u32>() + TpmuCapabilities::SIZE;
    fn len(&self) -> usize {
        self.capability.len() + self.data.len()
    }
}

impl TpmBuild for TpmsCapabilityData {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.capability.build(writer)?;
        self.data.build(writer)
    }
}

impl<'a> TpmParse<'a> for TpmsCapabilityData {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (capability, buf) = TpmCap::parse(buf)?;
        let (data, buf) = TpmuCapabilities::parse_tagged(capability, buf)?;
        Ok((Self { capability, data }, buf))
    }
}

tpm_struct! {
    /// From TPM 2.0 Part 2, 10.12.3, `TPMS_CERTIFY_INFO`
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsCertifyInfo {
        pub name: Tpm2bName,
        pub qualified_name: Tpm2bName,
    }
}

tpm_struct! {
    /// From TPM 2.0 Part 2, 10.6, `TPMS_CLOCK_INFO`
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsClockInfo {
        pub clock: u64,
        pub reset_count: u32,
        pub restart_count: u32,
        pub safe: TpmiYesNo,
    }
}

tpm_struct! {
    /// From TPM 2.0 Part 2, 10.12.6, `TPMS_COMMAND_AUDIT_INFO`
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsCommandAuditInfo {
        pub audit_counter: u64,
        pub digest_alg: TpmAlgId,
        pub audit_digest: Tpm2bDigest,
        pub command_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct TpmsContext {
        pub sequence: u64,
        pub saved_handle: crate::TpmTransient,
        pub hierarchy: TpmRh,
        pub context_blob: Tpm2b,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsContextData {
        pub integrity: Tpm2bDigest,
        pub encrypted: Tpm2bSensitive,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsCreationData {
        pub pcr_select: TpmlPcrSelection,
        pub pcr_digest: Tpm2bDigest,
        pub locality: TpmaLocality,
        pub parent_name_alg: TpmAlgId,
        pub parent_name: Tpm2bName,
        pub parent_qualified_name: Tpm2bName,
        pub outside_info: Tpm2bData,
    }
}

tpm_struct! {
    /// From TPM 2.0 Part 2, 10.12.5, `TPMS_CREATION_INFO`
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsCreationInfo {
        pub object_name: Tpm2bName,
        pub creation_hash: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsEccPoint {
        pub x: Tpm2bEccParameter,
        pub y: Tpm2bEccParameter,
    }
}

tpm_struct! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct TpmsEmpty {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsIdObject {
        pub integrity_hmac: Tpm2bDigest,
        pub enc_identity: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsKeyedhashParms {
        pub scheme: TpmtScheme,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsNvCertifyInfo {
        pub index_name: Tpm2bName,
        pub offset: u16,
        pub nv_contents: Tpm2bMaxNvBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsNvPublic {
        pub nv_index: u32,
        pub name_alg: TpmAlgId,
        pub attributes: TpmaNv,
        pub auth_policy: Tpm2bDigest,
        pub data_size: u16,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct TpmsPcrSelection {
    pub hash: TpmAlgId,
    pub pcr_select: TpmsPcrSelect,
}

impl TpmSized for TpmsPcrSelection {
    const SIZE: usize = TpmAlgId::SIZE + 1 + TPM_PCR_SELECT_MAX;

    fn len(&self) -> usize {
        self.hash.len() + 1 + self.pcr_select.deref().len()
    }
}

impl TpmBuild for TpmsPcrSelection {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.hash.build(writer)?;
        let size =
            u8::try_from(self.pcr_select.deref().len()).map_err(|_| TpmErrorKind::ValueTooLarge)?;
        size.build(writer)?;
        writer.write_bytes(&self.pcr_select)
    }
}

impl<'a> TpmParse<'a> for TpmsPcrSelection {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (hash, buf) = TpmAlgId::parse(buf)?;
        let (size, buf) = u8::parse(buf)?;
        let size = size as usize;

        if size > TPM_PCR_SELECT_MAX {
            return Err(TpmErrorKind::ValueTooLarge);
        }
        if buf.len() < size {
            return Err(TpmErrorKind::Boundary);
        }

        let (pcr_bytes, buf) = buf.split_at(size);
        let pcr_select = TpmBuffer::try_from(pcr_bytes)?;

        Ok((Self { hash, pcr_select }, buf))
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsQuoteInfo {
        pub pcr_select: TpmlPcrSelection,
        pub pcr_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsSensitiveCreate {
        pub user_auth: Tpm2bAuth,
        pub data: Tpm2bSensitiveData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsSessionAuditInfo {
        pub exclusive_session: TpmiYesNo,
        pub session_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsSymcipherParms {
        pub sym: TpmtSymDefObject,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsTimeAttestInfo {
        pub time: TpmsTimeInfo,
        pub firmware_version: u64,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsTimeInfo {
        pub time: u64,
        pub clock_info: TpmsClockInfo,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuSymMode {
    Aes(TpmAlgId),
    Sm4(TpmAlgId),
    Camellia(TpmAlgId),
    Xor,
    Null,
}

impl TpmTagged for TpmuSymMode {
    type Tag = TpmAlgId;
    type Value = ();
}

impl Default for TpmuSymMode {
    fn default() -> Self {
        Self::Null
    }
}

impl TpmSized for TpmuSymMode {
    const SIZE: usize = core::mem::size_of::<u16>();
    fn len(&self) -> usize {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) => val.len(),
            Self::Xor | Self::Null => 0,
        }
    }
}

impl<'a> TpmParseTagged<'a> for TpmuSymMode {
    fn parse_tagged(tag: TpmAlgId, buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        match tag {
            TpmAlgId::Aes => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                Ok((Self::Aes(val), buf))
            }
            TpmAlgId::Sm4 => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                Ok((Self::Sm4(val), buf))
            }
            TpmAlgId::Camellia => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                Ok((Self::Camellia(val), buf))
            }
            TpmAlgId::Xor => Ok((Self::Xor, buf)),
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

impl TpmBuild for TpmuSymMode {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            TpmuSymMode::Aes(val) | TpmuSymMode::Sm4(val) | TpmuSymMode::Camellia(val) => {
                val.build(writer)
            }
            TpmuSymMode::Xor | TpmuSymMode::Null => Ok(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct TpmtHa {
    pub hash_alg: TpmAlgId,
    pub digest: TpmuHa,
}

impl TpmTagged for TpmtHa {
    type Tag = TpmAlgId;
    type Value = TpmuHa;
}

impl TpmSized for TpmtHa {
    const SIZE: usize = size_of::<u16>() + TpmuHa::SIZE;
    fn len(&self) -> usize {
        self.hash_alg.len() + self.digest.len()
    }
}

impl TpmBuild for TpmtHa {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.hash_alg.build(writer)?;
        self.digest.build(writer)
    }
}

impl<'a> TpmParse<'a> for TpmtHa {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (hash_alg, buf) = TpmAlgId::parse(buf)?;
        let (digest, buf) = TpmuHa::parse_tagged(hash_alg, buf)?;
        Ok((Self { hash_alg, digest }, buf))
    }
}

tpm_struct! {
    /// A TPM key derivation function scheme, corresponding to `TPMT_KDF_SCHEME`.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtKdfScheme {
        pub scheme: TpmAlgId,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TpmtPublic {
    pub object_type: TpmAlgId,
    pub name_alg: TpmAlgId,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest,
    pub parameters: TpmuPublicParms,
    pub unique: TpmuPublicId,
}

impl TpmTagged for TpmtPublic {
    type Tag = TpmAlgId;
    type Value = TpmuPublicParms;
}

impl TpmSized for TpmtPublic {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        self.object_type.len()
            + self.name_alg.len()
            + self.object_attributes.len()
            + self.auth_policy.len()
            + self.parameters.len()
            + self.unique.len()
    }
}

impl TpmBuild for TpmtPublic {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.object_type.build(writer)?;
        self.name_alg.build(writer)?;
        self.object_attributes.build(writer)?;
        self.auth_policy.build(writer)?;
        self.parameters.build(writer)?;
        self.unique.build(writer)
    }
}

impl<'a> TpmParse<'a> for TpmtPublic {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (object_type, mut buf) = TpmAlgId::parse(buf)?;
        let (name_alg, rest) = TpmAlgId::parse(buf)?;
        buf = rest;
        let (object_attributes, rest) = TpmaObject::parse(buf)?;
        buf = rest;
        let (auth_policy, rest) = Tpm2bDigest::parse(buf)?;
        buf = rest;
        let (parameters, rest) = TpmuPublicParms::parse_tagged(object_type, buf)?;
        buf = rest;
        let (unique, rest) = TpmuPublicId::parse_tagged(object_type, buf)?;
        buf = rest;

        let public_area = Self {
            object_type,
            name_alg,
            object_attributes,
            auth_policy,
            parameters,
            unique,
        };

        Ok((public_area, buf))
    }
}

impl Default for TpmtPublic {
    fn default() -> Self {
        Self {
            object_type: TpmAlgId::Null,
            name_alg: TpmAlgId::Sha256,
            object_attributes: TpmaObject::empty(),
            auth_policy: Tpm2bDigest::default(),
            parameters: TpmuPublicParms::Null,
            unique: TpmuPublicId::Null,
        }
    }
}

tpm_struct! {
    /// A TPM signing scheme, corresponding to `TPMT_SIG_SCHEME`.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtScheme {
        pub scheme: TpmAlgId,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct TpmtSensitive {
    pub sensitive_type: TpmAlgId,
    pub auth_value: Tpm2bAuth,
    pub seed_value: Tpm2bDigest,
    pub sensitive: TpmuSensitiveComposite,
}

impl TpmTagged for TpmtSensitive {
    type Tag = TpmAlgId;
    type Value = TpmuSensitiveComposite;
}

impl TpmtSensitive {
    /// Constructs a `TpmtSensitive` from a given key algorithm and raw private key bytes.
    ///
    /// # Errors
    ///
    /// Returns a `TpmErrorKind::InvalidValue` if the key algorithm is not supported for this operation.
    pub fn from_private_bytes(
        key_alg: TpmAlgId,
        private_bytes: &[u8],
    ) -> Result<Self, TpmErrorKind> {
        let sensitive = match key_alg {
            TpmAlgId::Rsa => {
                TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::try_from(private_bytes)?)
            }
            TpmAlgId::Ecc => {
                TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::try_from(private_bytes)?)
            }
            TpmAlgId::KeyedHash => {
                TpmuSensitiveComposite::Bits(Tpm2bSensitiveData::try_from(private_bytes)?)
            }
            TpmAlgId::SymCipher => {
                TpmuSensitiveComposite::Sym(Tpm2bSymKey::try_from(private_bytes)?)
            }
            _ => return Err(TpmErrorKind::InvalidValue),
        };

        Ok(Self {
            sensitive_type: key_alg,
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::default(),
            sensitive,
        })
    }
}

impl TpmSized for TpmtSensitive {
    const SIZE: usize =
        size_of::<TpmAlgId>() + Tpm2bAuth::SIZE + Tpm2bDigest::SIZE + TpmuSensitiveComposite::SIZE;
    fn len(&self) -> usize {
        self.sensitive_type.len()
            + self.auth_value.len()
            + self.seed_value.len()
            + self.sensitive.len()
    }
}

impl TpmBuild for TpmtSensitive {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.sensitive_type.build(writer)?;
        self.auth_value.build(writer)?;
        self.seed_value.build(writer)?;
        self.sensitive.build(writer)
    }
}

impl<'a> TpmParse<'a> for TpmtSensitive {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (sensitive_type, buf) = TpmAlgId::parse(buf)?;
        let (auth_value, buf) = Tpm2bAuth::parse(buf)?;
        let (seed_value, buf) = Tpm2bDigest::parse(buf)?;
        let (sensitive, buf) = TpmuSensitiveComposite::parse_tagged(sensitive_type, buf)?;

        Ok((
            Self {
                sensitive_type,
                auth_value,
                seed_value,
                sensitive,
            },
            buf,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct TpmtSymDef {
    pub algorithm: TpmAlgId,
    pub key_bits: TpmuSymKeyBits,
    pub mode: TpmuSymMode,
}

impl TpmTagged for TpmtSymDef {
    type Tag = TpmAlgId;
    type Value = TpmuSymKeyBits;
}

impl TpmSized for TpmtSymDef {
    const SIZE: usize = TpmAlgId::SIZE + TpmuSymKeyBits::SIZE + TpmAlgId::SIZE;
    fn len(&self) -> usize {
        if self.algorithm == TpmAlgId::Null {
            self.algorithm.len()
        } else {
            self.algorithm.len() + self.key_bits.len() + self.mode.len()
        }
    }
}

impl TpmBuild for TpmtSymDef {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.algorithm.build(writer)?;
        if self.algorithm != TpmAlgId::Null {
            self.key_bits.build(writer)?;
            self.mode.build(writer)?;
        }
        Ok(())
    }
}

impl<'a> TpmParse<'a> for TpmtSymDef {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (algorithm, buf) = TpmAlgId::parse(buf)?;
        if algorithm == TpmAlgId::Null {
            Ok((
                Self {
                    algorithm,
                    key_bits: TpmuSymKeyBits::Null,
                    mode: TpmuSymMode::Null,
                },
                buf,
            ))
        } else {
            let (key_bits, buf) = TpmuSymKeyBits::parse_tagged(algorithm, buf)?;
            let (mode, buf) = TpmuSymMode::parse_tagged(algorithm, buf)?;
            Ok((
                Self {
                    algorithm,
                    key_bits,
                    mode,
                },
                buf,
            ))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct TpmtSymDefObject {
    pub algorithm: TpmAlgId,
    pub key_bits: TpmuSymKeyBits,
    pub mode: TpmuSymMode,
}

impl TpmTagged for TpmtSymDefObject {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmtSymDefObject {
    const SIZE: usize = size_of::<TpmAlgId>() + size_of::<u16>() + size_of::<TpmAlgId>();
    fn len(&self) -> usize {
        if self.algorithm == TpmAlgId::Null {
            self.algorithm.len()
        } else {
            self.algorithm.len() + self.key_bits.len() + self.mode.len()
        }
    }
}

impl TpmBuild for TpmtSymDefObject {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.algorithm.build(writer)?;
        if self.algorithm != TpmAlgId::Null {
            self.key_bits.build(writer)?;
            self.mode.build(writer)?;
        }
        Ok(())
    }
}

impl<'a> TpmParse<'a> for TpmtSymDefObject {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (algorithm, buf) = TpmAlgId::parse(buf)?;
        if algorithm == TpmAlgId::Null {
            Ok((
                Self {
                    algorithm,
                    key_bits: TpmuSymKeyBits::Null,
                    mode: TpmuSymMode::Null,
                },
                buf,
            ))
        } else {
            let (key_bits, buf) = TpmuSymKeyBits::parse_tagged(algorithm, buf)?;
            let (mode, buf) = TpmuSymMode::parse_tagged(algorithm, buf)?;
            Ok((
                Self {
                    algorithm,
                    key_bits,
                    mode,
                },
                buf,
            ))
        }
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmtTkAuth {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmtTkCreation {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtTkHashcheck {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuAttest {
    Certify(TpmsCertifyInfo),
    Creation(TpmsCreationInfo),
    Quote(TpmsQuoteInfo),
    CommandAudit(TpmsCommandAuditInfo),
    SessionAudit(TpmsSessionAuditInfo),
    Time(TpmsTimeAttestInfo),
    Nv(TpmsNvCertifyInfo),
}

impl TpmTagged for TpmuAttest {
    type Tag = TpmSt;
    type Value = ();
}

impl TpmSized for TpmuAttest {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Certify(val) => val.len(),
            Self::Creation(val) => val.len(),
            Self::Quote(val) => val.len(),
            Self::CommandAudit(val) => val.len(),
            Self::SessionAudit(val) => val.len(),
            Self::Time(val) => val.len(),
            Self::Nv(val) => val.len(),
        }
    }
}

impl TpmBuild for TpmuAttest {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Certify(val) => val.build(writer),
            Self::Creation(val) => val.build(writer),
            Self::Quote(val) => val.build(writer),
            Self::CommandAudit(val) => val.build(writer),
            Self::SessionAudit(val) => val.build(writer),
            Self::Time(val) => val.build(writer),
            Self::Nv(val) => val.build(writer),
        }
    }
}

impl<'a> TpmParseTagged<'a> for TpmuAttest {
    fn parse_tagged(tag: TpmSt, buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        match tag {
            TpmSt::AttestCertify => {
                let (val, buf) = TpmsCertifyInfo::parse(buf)?;
                Ok((Self::Certify(val), buf))
            }
            TpmSt::AttestCreation => {
                let (val, buf) = TpmsCreationInfo::parse(buf)?;
                Ok((Self::Creation(val), buf))
            }
            TpmSt::AttestQuote => {
                let (val, buf) = TpmsQuoteInfo::parse(buf)?;
                Ok((Self::Quote(val), buf))
            }
            TpmSt::AttestCommandAudit => {
                let (val, buf) = TpmsCommandAuditInfo::parse(buf)?;
                Ok((Self::CommandAudit(val), buf))
            }
            TpmSt::AttestSessionAudit => {
                let (val, buf) = TpmsSessionAuditInfo::parse(buf)?;
                Ok((Self::SessionAudit(val), buf))
            }
            TpmSt::AttestTime => {
                let (val, buf) = TpmsTimeAttestInfo::parse(buf)?;
                Ok((Self::Time(val), buf))
            }
            TpmSt::AttestNv => {
                let (val, buf) = TpmsNvCertifyInfo::parse(buf)?;
                Ok((Self::Nv(val), buf))
            }
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

impl Default for TpmuAttest {
    fn default() -> Self {
        Self::Quote(TpmsQuoteInfo::default())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuCapabilities {
    Algs(TpmlAlgProperty),
    Handles(TpmlHandle),
    Pcrs(TpmlPcrSelection),
}

impl TpmTagged for TpmuCapabilities {
    type Tag = TpmCap;
    type Value = ();
}

impl TpmSized for TpmuCapabilities {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Algs(algs) => algs.len(),
            Self::Handles(handles) => handles.len(),
            Self::Pcrs(pcrs) => pcrs.len(),
        }
    }
}

impl TpmBuild for TpmuCapabilities {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            TpmuCapabilities::Algs(algs) => algs.build(writer),
            TpmuCapabilities::Handles(handles) => handles.build(writer),
            TpmuCapabilities::Pcrs(pcrs) => pcrs.build(writer),
        }
    }
}

impl<'a> TpmParseTagged<'a> for TpmuCapabilities {
    fn parse_tagged(tag: TpmCap, buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        match tag {
            TpmCap::Algs => {
                let (algs, buf) = TpmlAlgProperty::parse(buf)?;
                Ok((TpmuCapabilities::Algs(algs), buf))
            }
            TpmCap::Handles => {
                let (handles, buf) = TpmlHandle::parse(buf)?;
                Ok((TpmuCapabilities::Handles(handles), buf))
            }
            TpmCap::Pcrs => {
                let (pcrs, buf) = TpmlPcrSelection::parse(buf)?;
                Ok((TpmuCapabilities::Pcrs(pcrs), buf))
            }
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuHa {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
    Sm3_256([u8; 32]),
}

impl TpmTagged for TpmuHa {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmBuild for TpmuHa {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        writer.write_bytes(self)
    }
}

impl<'a> TpmParseTagged<'a> for TpmuHa {
    fn parse_tagged(tag: TpmAlgId, buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let digest_size = tpm_hash_size(&tag).ok_or(TpmErrorKind::InvalidValue)?;
        if buf.len() < digest_size {
            return Err(TpmErrorKind::Boundary);
        }

        let (digest_bytes, buf) = buf.split_at(digest_size);

        macro_rules! match_hash_alg_to_digest_variant {
            ($tag:expr, $bytes:expr) => {
                match $tag {
                    TpmAlgId::Sha1 => {
                        TpmuHa::Sha1($bytes.try_into().map_err(|_| TpmErrorKind::InternalError)?)
                    }
                    TpmAlgId::Sha256 => {
                        TpmuHa::Sha256($bytes.try_into().map_err(|_| TpmErrorKind::InternalError)?)
                    }
                    TpmAlgId::Sha384 => {
                        TpmuHa::Sha384($bytes.try_into().map_err(|_| TpmErrorKind::InternalError)?)
                    }
                    TpmAlgId::Sha512 => {
                        TpmuHa::Sha512($bytes.try_into().map_err(|_| TpmErrorKind::InternalError)?)
                    }
                    TpmAlgId::Sm3_256 => {
                        TpmuHa::Sm3_256($bytes.try_into().map_err(|_| TpmErrorKind::InternalError)?)
                    }
                    _ => return Err(TpmErrorKind::InvalidValue),
                }
            };
        }

        let digest = match_hash_alg_to_digest_variant!(tag, digest_bytes);

        Ok((digest, buf))
    }
}

impl Default for TpmuHa {
    fn default() -> Self {
        Self::Sha256([0; 32])
    }
}

impl TpmSized for TpmuHa {
    const SIZE: usize = 64;
    fn len(&self) -> usize {
        match self {
            Self::Sha1(d) => d.len(),
            Self::Sha256(d) | Self::Sm3_256(d) => d.len(),
            Self::Sha384(d) => d.len(),
            Self::Sha512(d) => d.len(),
        }
    }
}

impl Deref for TpmuHa {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Sha1(d) => d,
            Self::Sha256(d) | Self::Sm3_256(d) => d,
            Self::Sha384(d) => d,
            Self::Sha512(d) => d,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuPublicId {
    KeyedHash(Tpm2bDigest),
    SymCipher(Tpm2bSymKey),
    Rsa(Tpm2bPublicKeyRsa),
    Ecc(TpmsEccPoint),
    Null,
}

impl TpmTagged for TpmuPublicId {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmuPublicId {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::KeyedHash(data) => data.len(),
            Self::SymCipher(data) => data.len(),
            Self::Rsa(data) => data.len(),
            Self::Ecc(point) => point.len(),
            Self::Null => 0,
        }
    }
}

impl TpmBuild for TpmuPublicId {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            TpmuPublicId::KeyedHash(data) => data.build(writer),
            TpmuPublicId::SymCipher(data) => data.build(writer),
            TpmuPublicId::Rsa(data) => data.build(writer),
            TpmuPublicId::Ecc(point) => point.build(writer),
            TpmuPublicId::Null => Ok(()),
        }
    }
}

impl<'a> TpmParseTagged<'a> for TpmuPublicId {
    /// Parses `TpmuPublicId` from the given buffer
    ///
    /// # Errors
    ///
    /// * `TpmErrorKind::Boundary` if the buffer is too small to contain the object.
    /// * `TpmErrorKind::InvalidValue` if a value in the buffer is invalid for the target type.
    fn parse_tagged(tag: TpmAlgId, buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        match tag {
            TpmAlgId::KeyedHash => {
                let (val, rest) = Tpm2bDigest::parse(buf)?;
                Ok((Self::KeyedHash(val), rest))
            }
            TpmAlgId::SymCipher => {
                let (val, rest) = Tpm2bSymKey::parse(buf)?;
                Ok((Self::SymCipher(val), rest))
            }
            TpmAlgId::Rsa => {
                let (val, rest) = Tpm2bPublicKeyRsa::parse(buf)?;
                Ok((Self::Rsa(val), rest))
            }
            TpmAlgId::Ecc => {
                let (point, rest) = TpmsEccPoint::parse(buf)?;
                Ok((Self::Ecc(point), rest))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

impl Default for TpmuPublicId {
    fn default() -> Self {
        Self::Null
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuPublicParms {
    KeyedHash {
        details: TpmsKeyedhashParms,
    },
    SymCipher {
        details: TpmsSymcipherParms,
    },
    Rsa {
        symmetric: TpmtSymDefObject,
        scheme: TpmtScheme,
        key_bits: u16,
        exponent: u32,
    },
    Ecc {
        symmetric: TpmtSymDefObject,
        scheme: TpmtScheme,
        curve_id: TpmEccCurve,
        kdf: TpmtKdfScheme,
    },
    Null,
}

impl TpmTagged for TpmuPublicParms {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmuPublicParms {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::KeyedHash { details } => details.len(),
            Self::SymCipher { details } => details.len(),
            Self::Rsa {
                symmetric,
                scheme,
                key_bits,
                exponent,
            } => symmetric.len() + scheme.len() + key_bits.len() + exponent.len(),
            Self::Ecc {
                symmetric,
                scheme,
                curve_id,
                kdf,
            } => symmetric.len() + scheme.len() + curve_id.len() + kdf.len(),
            Self::Null => 0,
        }
    }
}

impl TpmBuild for TpmuPublicParms {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            TpmuPublicParms::KeyedHash { details } => details.build(writer),
            TpmuPublicParms::SymCipher { details } => details.build(writer),
            TpmuPublicParms::Rsa {
                symmetric,
                scheme,
                key_bits,
                exponent,
            } => {
                symmetric.build(writer)?;
                scheme.build(writer)?;
                key_bits.build(writer)?;
                exponent.build(writer)
            }
            TpmuPublicParms::Ecc {
                symmetric,
                scheme,
                curve_id,
                kdf,
            } => {
                symmetric.build(writer)?;
                scheme.build(writer)?;
                (*curve_id as u16).build(writer)?;
                kdf.build(writer)
            }
            TpmuPublicParms::Null => Ok(()),
        }
    }
}

impl<'a> TpmParseTagged<'a> for TpmuPublicParms {
    /// Parses `TpmuPublicParms` from the given buffer
    ///
    /// # Errors
    ///
    /// * `TpmErrorKind::Boundary` if the buffer is too small to contain the object.
    /// * `TpmErrorKind::InvalidValue` if a value in the buffer is invalid for the target type.
    fn parse_tagged(tag: TpmAlgId, buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        match tag {
            TpmAlgId::KeyedHash => {
                let (details, buf) = TpmsKeyedhashParms::parse(buf)?;
                Ok((Self::KeyedHash { details }, buf))
            }
            TpmAlgId::SymCipher => {
                let (details, buf) = TpmsSymcipherParms::parse(buf)?;
                Ok((Self::SymCipher { details }, buf))
            }
            TpmAlgId::Rsa => {
                let (symmetric, buf) = TpmtSymDefObject::parse(buf)?;
                let (scheme, buf) = TpmtScheme::parse(buf)?;
                let (key_bits, buf) = u16::parse(buf)?;
                let (exponent, buf) = u32::parse(buf)?;
                Ok((
                    Self::Rsa {
                        symmetric,
                        scheme,
                        key_bits,
                        exponent,
                    },
                    buf,
                ))
            }
            TpmAlgId::Ecc => {
                let (symmetric, buf) = TpmtSymDefObject::parse(buf)?;
                let (scheme, buf) = TpmtScheme::parse(buf)?;
                let (curve_id_raw, buf) = u16::parse(buf)?;
                let curve_id = TpmEccCurve::try_from(curve_id_raw).map_err(|()| {
                    TpmErrorKind::InvalidDiscriminant {
                        type_name: "TpmEccCurve",
                        value: u64::from(curve_id_raw),
                    }
                })?;
                let (kdf, buf) = TpmtKdfScheme::parse(buf)?;
                Ok((
                    Self::Ecc {
                        symmetric,
                        scheme,
                        curve_id,
                        kdf,
                    },
                    buf,
                ))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuSensitiveComposite {
    Rsa(Tpm2bPrivateKeyRsa),
    Ecc(Tpm2bEccParameter),
    Bits(Tpm2bSensitiveData),
    Sym(Tpm2bSymKey),
}

impl TpmTagged for TpmuSensitiveComposite {
    type Tag = TpmAlgId;
    type Value = ();
}

impl Default for TpmuSensitiveComposite {
    fn default() -> Self {
        Self::Rsa(Tpm2bPrivateKeyRsa::default())
    }
}

impl TpmSized for TpmuSensitiveComposite {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Rsa(val) => val.len(),
            Self::Ecc(val) => val.len(),
            Self::Bits(val) => val.len(),
            Self::Sym(val) => val.len(),
        }
    }
}

impl TpmBuild for TpmuSensitiveComposite {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            TpmuSensitiveComposite::Rsa(val) => val.build(writer),
            TpmuSensitiveComposite::Ecc(val) => val.build(writer),
            TpmuSensitiveComposite::Bits(val) => val.build(writer),
            TpmuSensitiveComposite::Sym(val) => val.build(writer),
        }
    }
}

impl<'a> TpmParseTagged<'a> for TpmuSensitiveComposite {
    /// Parses `TpmuSensitiveComposite` from a buffer based on the sensitive type.
    ///
    /// # Errors
    ///
    /// * `TpmErrorKind::Boundary` if the buffer is too small to contain the object.
    /// * `TpmErrorKind::InvalidValue` if the `sensitive_type` is not a valid object
    ///   type for this union, or if an inner value fails to parse.
    fn parse_tagged(tag: TpmAlgId, buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        match tag {
            TpmAlgId::Rsa => {
                let (val, buf) = Tpm2bPrivateKeyRsa::parse(buf)?;
                Ok((Self::Rsa(val), buf))
            }
            TpmAlgId::Ecc => {
                let (val, buf) = Tpm2bEccParameter::parse(buf)?;
                Ok((Self::Ecc(val), buf))
            }
            TpmAlgId::KeyedHash => {
                let (val, buf) = Tpm2bSensitiveData::parse(buf)?;
                Ok((Self::Bits(val), buf))
            }
            TpmAlgId::SymCipher => {
                let (val, buf) = Tpm2bSymKey::parse(buf)?;
                Ok((Self::Sym(val), buf))
            }
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuSymKeyBits {
    Aes(u16),
    Sm4(u16),
    Camellia(u16),
    Null,
}

impl TpmTagged for TpmuSymKeyBits {
    type Tag = TpmAlgId;
    type Value = ();
}

impl Default for TpmuSymKeyBits {
    fn default() -> Self {
        Self::Null
    }
}

impl TpmSized for TpmuSymKeyBits {
    const SIZE: usize = core::mem::size_of::<u16>();
    fn len(&self) -> usize {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) => val.len(),
            Self::Null => 0,
        }
    }
}

impl<'a> TpmParseTagged<'a> for TpmuSymKeyBits {
    /// Parses `TpmuSymKeyBits` from the given buffer
    ///
    /// # Errors
    ///
    /// * `TpmErrorKind::Boundary` if the buffer is too small to contain the object.
    /// * `TpmErrorKind::InvalidValue` if a value in the buffer is invalid for the target type.
    fn parse_tagged(tag: TpmAlgId, buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        match tag {
            TpmAlgId::Aes => {
                let (val, buf) = u16::parse(buf)?;
                Ok((Self::Aes(val), buf))
            }
            TpmAlgId::Sm4 => {
                let (val, buf) = u16::parse(buf)?;
                Ok((Self::Sm4(val), buf))
            }
            TpmAlgId::Camellia => {
                let (val, buf) = u16::parse(buf)?;
                Ok((Self::Camellia(val), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

impl TpmBuild for TpmuSymKeyBits {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            TpmuSymKeyBits::Aes(val) | TpmuSymKeyBits::Sm4(val) | TpmuSymKeyBits::Camellia(val) => {
                val.build(writer)
            }
            TpmuSymKeyBits::Null => Ok(()),
        }
    }
}

tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bPublic,
    TpmtPublic
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bTemplate,
    TpmtPublic
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bSensitive,
    TpmtSensitive
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bSensitiveCreate,
    TpmsSensitiveCreate
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bAttest,
    TpmsAttest
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bContextData,
    TpmsContextData
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bCreationData,
    TpmsCreationData
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bEccPoint,
    TpmsEccPoint
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bIdObject,
    TpmsIdObject
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bNvPublic,
    TpmsNvPublic
);
