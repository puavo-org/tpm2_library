// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

pub mod tpma;
pub mod tpms;
pub mod tpmt;
pub mod tpmu;

pub use tpma::*;
pub use tpms::*;
pub use tpmt::*;
pub use tpmu::*;

use crate::{
    tpm2b, tpm2b_struct, tpm_bool, tpm_enum, tpml, TpmErrorKind, TpmSized, TPM_MAX_COMMAND_SIZE,
};
use core::{
    convert::TryFrom,
    fmt::{self, Debug, Display, Formatter},
};

pub const MAX_DIGEST_SIZE: usize = 64;
pub const MAX_ECC_KEY_BYTES: usize = 66;
pub const MAX_SYM_KEY_BYTES: usize = 32;
pub const MAX_RSA_KEY_BYTES: usize = 512;
pub const MAX_SENSITIVE_DATA: usize = 256;
pub const MAX_BUFFER_SIZE: usize = 1024;
pub const MAX_NV_BUFFER_SIZE: usize = 1024;
pub const MAX_PRIVATE_SIZE: usize = 1408;

tpm2b!(Tpm2b, TPM_MAX_COMMAND_SIZE);
tpm2b!(Tpm2bAuth, MAX_DIGEST_SIZE);
tpm2b!(Tpm2bDigest, MAX_DIGEST_SIZE);
tpm2b!(Tpm2bEccParameter, MAX_ECC_KEY_BYTES);
tpm2b!(Tpm2bEncryptedSecret, MAX_ECC_KEY_BYTES);
tpm2b!(Tpm2bMaxBuffer, MAX_BUFFER_SIZE);
tpm2b!(Tpm2bMaxNvBuffer, MAX_NV_BUFFER_SIZE);
tpm2b!(Tpm2bName, { MAX_DIGEST_SIZE + 2 });
tpm2b!(Tpm2bNonce, MAX_DIGEST_SIZE);
tpm2b!(Tpm2bPrivate, MAX_PRIVATE_SIZE);
tpm2b!(Tpm2bPrivateKeyRsa, MAX_RSA_KEY_BYTES);
tpm2b!(Tpm2bPublicKeyRsa, MAX_RSA_KEY_BYTES);
tpm2b!(Tpm2bSensitiveData, MAX_SENSITIVE_DATA);
tpm2b!(Tpm2bSymKey, MAX_SYM_KEY_BYTES);
tpm2b!(Tpm2bData, MAX_SENSITIVE_DATA);

tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bPublic,
    TpmtPublic
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bSensitiveCreate,
    TpmsSensitiveCreate
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    Tpm2bSensitive,
    TpmtSensitive
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bCreationData,
    TpmsCreationData
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    Tpm2bAttest,
    TpmsAttest
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    Tpm2bNvPublic,
    TpmsNvPublic
);
tpm2b_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bIdObject,
    TpmsIdObject
);

tpm_enum! {
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
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    pub enum TpmCap(u32) {
        (Algs, 0x0000_0000, "TPM_CAP_ALGS"),
        (Handles, 0x0000_0001, "TPM_CAP_HANDLES"),
        (Commands, 0x0000_0002, "TPM_CAP_COMMANDS"),
        (Pcrs, 0x0000_0005, "TPM_CAP_PCRS"),
    }
}

tpm_enum! {
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
    pub enum TpmCc(u32) {
        (NvUndefineSpaceSpecial, 0x0000_011F, "TPM_CC_NV_UndefineSpaceSpecial"),
        (EvictControl, 0x0000_0120, "TPM_CC_EvictControl"),
        (NvUndefineSpace, 0x0000_0122, "TPM_CC_NV_UndefineSpace"),
        (NvDefineSpace, 0x0000_012A, "TPM_CC_NV_DefineSpace"),
        (CreatePrimary, 0x0000_0131, "TPM_CC_CreatePrimary"),
        (NvGlobalWriteLock, 0x0000_0132, "TPM_CC_NV_GlobalWriteLock"),
        (GetCommandAuditDigest, 0x0000_0133, "TPM_CC_GetCommandAuditDigest"),
        (NvIncrement, 0x0000_0134, "TPM_CC_NV_Increment"),
        (NvSetBits, 0x0000_0135, "TPM_CC_NV_SetBits"),
        (NvExtend, 0x0000_0136, "TPM_CC_NV_Extend"),
        (NvWrite, 0x0000_0137, "TPM_CC_NV_Write"),
        (NvWriteLock, 0x0000_0138, "TPM_CC_NV_WriteLock"),
        (DictionaryAttackLockReset, 0x0000_0139, "TPM_CC_DictionaryAttackLockReset"),
        (NvChangeAuth, 0x0000_013B, "TPM_CC_NV_ChangeAuth"),
        (PcrEvent, 0x0000_013C, "TPM_CC_PCR_Event"),
        (IncrementalSelfTest, 0x0000_0142, "TPM_CC_IncrementalSelfTest"),
        (SelfTest, 0x0000_0143, "TPM_CC_SelfTest"),
        (Startup, 0x0000_0144, "TPM_CC_Startup"),
        (Shutdown, 0x0000_0145, "TPM_CC_Shutdown"),
        (ActivateCredential, 0x0000_0147, "TPM_CC_ActivateCredential"),
        (Certify, 0x0000_0148, "TPM_CC_Certify"),
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
        (Import, 0x0000_0156, "TPM_CC_Import"),
        (Load, 0x0000_0157, "TPM_CC_Load"),
        (Quote, 0x0000_0158, "TPM_CC_Quote"),
        (Sign, 0x0000_015D, "TPM_CC_Sign"),
        (Unseal, 0x0000_015E, "TPM_CC_Unseal"),
        (ContextLoad, 0x0000_0161, "TPM_CC_ContextLoad"),
        (ContextSave, 0x0000_0162, "TPM_CC_ContextSave"),
        (FlushContext, 0x0000_0165, "TPM_CC_FlushContext"),
        (LoadExternal, 0x0000_0167, "TPM_CC_LoadExternal"),
        (MakeCredential, 0x0000_0168, "TPM_CC_MakeCredential"),
        (NvReadPublic, 0x0000_0169, "TPM_CC_NV_ReadPublic"),
        (PolicyAuthValue, 0x0000_016B, "TPM_CC_PolicyAuthValue"),
        (PolicyCommandCode, 0x0000_016C, "TPM_CC_PolicyCommandCode"),
        (PolicyOR, 0x0000_0171, "TPM_CC_PolicyOR"),
        (ReadPublic, 0x0000_0173, "TPM_CC_ReadPublic"),
        (StartAuthSession, 0x0000_0176, "TPM_CC_StartAuthSession"),
        (VerifySignature, 0x0000_0177, "TPM_CC_VerifySignature"),
        (GetCapability, 0x0000_017A, "TPM_CC_GetCapability"),
        (GetTestResult, 0x0000_017C, "TPM_CC_GetTestResult"),
        (Hash, 0x0000_017D, "TPM_CC_Hash"),
        (PcrRead, 0x0000_017E, "TPM_CC_PCR_Read"),
        (PolicyPcr, 0x0000_017F, "TPM_CC_PolicyPCR"),
        (PolicyRestart, 0x0000_0180, "TPM_CC_PolicyRestart"),
        (NvCertify, 0x0000_0184, "TPM_CC_NV_Certify"),
        (PolicyGetDigest, 0x0000_0189, "TPM_CC_PolicyGetDigest"),
        (PolicyPassword, 0x0000_018C, "TPM_CC_PolicyPassword"),
        (NvDefineSpace2, 0x0000_019D, "TPM_CC_NV_DefineSpace2"),
        (NvReadPublic2, 0x0000_019E, "TPM_CC_NV_ReadPublic2"),
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
            Self::Parameter(i) => write!(f, "parameter[{i}]"),
            Self::Handle(i) => write!(f, "handle[{i}]"),
            Self::Session(i) => write!(f, "session[{i}]"),
        }
    }
}

tpm_enum! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    #[allow(clippy::upper_case_acronyms)]
    pub enum TpmRcBase(u32) {
        (Success, 0x0000, "TPM_RC_SUCCESS"),
        (BadTag, 0x001E, "TPM_RC_BAD_TAG"),
        (Initialize, TPM_RC_VER1, "TPM_RC_INITIALIZE"),
        (Failure, TPM_RC_VER1 | 0x001, "TPM_RC_FAILURE"),
        (AuthMissing, TPM_RC_VER1 | 0x025, "TPM_RC_AUTH_MISSING"),
        (CommandSize, TPM_RC_VER1 | 0x042, "TPM_RC_COMMAND_SIZE"),
        (Sensitive, TPM_RC_VER1 | 0x055, "TPM_RC_SENSITIVE"),
        (Asymmetric, TPM_RC_FMT1 | 0x001, "TPM_RC_ASYMMETRIC"),
        (Attributes, TPM_RC_FMT1 | 0x002, "TPM_RC_ATTRIBUTES"),
        (Value, TPM_RC_FMT1 | 0x004, "TPM_RC_VALUE"),
        (Handle, TPM_RC_FMT1 | 0x00B, "TPM_RC_HANDLE"),
        (AuthFail, TPM_RC_FMT1 | 0x00E, "TPM_RC_AUTH_FAIL"),
        (BadAuth, TPM_RC_FMT1 | 0x022, "TPM_RC_BAD_AUTH"),
        (Curve, TPM_RC_FMT1 | 0x026, "TPM_RC_CURVE"),
        (ContextGap, TPM_RC_WARN | 0x001, "TPM_RC_CONTEXT_GAP"),
        (NvUnavailable, TPM_RC_WARN | 0x023, "TPM_RC_NV_UNAVAILABLE"),
    }
}

#[must_use]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct TpmRc(u32);

impl TpmRc {
    /// Returns the base error code, stripping any handle, parameter, or session index.
    ///
    /// # Errors
    ///
    /// Returns a `TpmErrorKind::InvalidDiscriminant` if the response code does not correspond
    /// to a known base error code.
    pub fn base(self) -> Result<TpmRcBase, TpmErrorKind> {
        let value = self.0;
        let base_code = if (value & TPM_RC_FMT1) != 0 {
            TPM_RC_FMT1 | (value & TPM_RC_FMT1_ERROR_MASK)
        } else {
            value
        };
        TpmRcBase::try_from(base_code).map_err(|()| TpmErrorKind::InvalidDiscriminant {
            type_name: "TpmRcBase",
            value: u64::from(base_code),
        })
    }

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
            Some(TpmRcIndex::Session(n - 8))
        }
    }

    #[must_use]
    pub fn value(self) -> u32 {
        self.0
    }
    #[must_use]
    pub fn is_warning(self) -> bool {
        (self.0 & TPM_RC_WARN) == TPM_RC_WARN
    }
    #[must_use]
    pub fn is_error(self) -> bool {
        !self.is_warning() && self.0 != 0
    }
}

impl crate::TpmSized for TpmRc {
    const SIZE: usize = core::mem::size_of::<u32>();
    fn len(&self) -> usize {
        Self::SIZE
    }
}

impl crate::TpmBuild for TpmRc {
    fn build(&self, writer: &mut crate::TpmWriter) -> crate::TpmResult<()> {
        self.0.build(writer)
    }
}

impl<'a> crate::TpmParse<'a> for TpmRc {
    fn parse(buf: &'a [u8]) -> crate::TpmResult<(Self, &'a [u8])> {
        let (val, remainder) = u32::parse(buf)?;
        let rc = Self::try_from(val)?;
        Ok((rc, remainder))
    }
}

impl TryFrom<u32> for TpmRc {
    type Error = TpmErrorKind;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let base_code = if (value & TPM_RC_FMT1) != 0 {
            TPM_RC_FMT1 | (value & TPM_RC_FMT1_ERROR_MASK)
        } else {
            value
        };
        TpmRcBase::try_from(base_code).map_err(|()| TpmErrorKind::InvalidDiscriminant {
            type_name: "TpmRcBase",
            value: u64::from(base_code),
        })?;
        Ok(Self(value))
    }
}

impl From<TpmRcBase> for TpmRc {
    fn from(value: TpmRcBase) -> Self {
        Self(value as u32)
    }
}

impl Display for TpmRc {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Ok(base) = self.base() {
            if let Some(index) = self.index() {
                write!(f, "[{base}, {index}]")
            } else {
                write!(f, "{base}")
            }
        } else {
            write!(f, "TPM_RC_UNKNOWN(0x{:08X})", self.0)
        }
    }
}

tpm_enum! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    pub enum TpmRh(u32) {
        (Owner, 0x4000_0001, "TPM_RH_OWNER"),
        #[default]
        (Null, 0x4000_0007, "TPM_RH_NULL"),
        (Password, 0x4000_0009, "TPM_RH_PW"),
        (Lockout, 0x4000_000A, "TPM_RH_LOCKOUT"),
        (Endorsement, 0x4000_000B, "TPM_RH_ENDORSEMENT"),
        (Platform, 0x4000_000C, "TPM_RH_PLATFORM"),
        (TransientFirst, 0x8000_0000, "First transient handle"),
        (PersistentFirst, 0x8100_0000, "First persistent handle"),
    }
}

tpm_enum! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
    pub enum TpmSe(u8) {
        #[default]
        (Hmac, 0x00, "TPM_SE_HMAC"),
        (Policy, 0x01, "TPM_SE_POLICY"),
        (Trial, 0x03, "TPM_SE_TRIAL"),
    }
}

tpm_enum! {
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
        (AttestNvDigest, 0x801C, "TPM_ST_ATTEST_NV_DIGEST"),
        (Creation, 0x8021, "TPM_ST_CREATION"),
        (Verified, 0x8022, "TPM_ST_VERIFIED"),
        (AuthSecret, 0x8023, "TPM_ST_AUTH_SECRET"),
        (HashCheck, 0x8024, "TPM_ST_HASHCHECK"),
        (AuthSigned, 0x8025, "TPM_ST_AUTH_SIGNED"),
    }
}

tpm_enum! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
    pub enum TpmSu(u16) {
        (Clear, 0x0000, "TPM_SU_CLEAR"),
        #[default]
        (State, 0x0001, "TPM_SU_STATE"),
    }
}

tpm_bool! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct TpmiYesNo(bool);
}

tpml!(TpmlAlgProperty, TpmsAlgProperty, 64);
tpml!(TpmlAlg, TpmAlgId, 64);
tpml!(TpmlDigest, Tpm2bDigest, 8);
tpml!(TpmlDigestValues, TpmtHa, 8);
tpml!(TpmlHandle, u32, 128);
tpml!(TpmlPcrSelection, TpmsPcrSelection, 8);
