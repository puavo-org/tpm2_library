// SPDX-License-Identifier: MIT
#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use bitflags::bitflags;
use core::convert::From;
use core::fmt;
use core::option::Option;
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind, Read, Result, Write};
use strum_macros::FromRepr;

/// `TPM_ALG_ID`
#[derive(FromRepr, Debug, PartialEq)]
#[repr(u16)]
pub enum TpmAlg {
    /// `TPM_AG_ERROR`
    Error = 0x0000,
    /// `TPM_ALG_RSA`
    Rsa = 0x0001,
    /// `TPM_ALG_SHA1`
    Sha1 = 0x0004,
    /// `TPM_ALG_HMAC`
    Hmac = 0x0005,
    /// `TPM_ALG_AES`
    Aes = 0x0006,
    /// `TPM_ALG_MGF1`
    Mgf1 = 0x0007,
    /// `TPM_ALG_KEYEDHASH`
    KeyedHash = 0x0008,
    /// `TPM_ALG_XOR`
    Xor = 0x000A,
    /// `TPM_ALG_SHA256`
    Sha256 = 0x000B,
    /// `TPM_ALG_SHA384`
    Sha384 = 0x000C,
    /// `TPM_ALG_SHA512`
    Sha512 = 0x000D,
    /// `TPM_ALG_NULL`
    Null = 0x0010,
    /// `TPM_ALG_SM3_256`
    Sm3 = 0x0012,
    /// `TPM_ALG_SM4`
    Sm4 = 0x0013,
    /// `TPM_ALG_RSASSA`
    Rsassa = 0x0014,
    /// `TPM_ALG_RSAES`
    Rsaes = 0x0015,
    /// `TPM_ALG_RSAPSS`
    Rsapss = 0x0016,
    /// `TPM_ALG_OAEP`
    Oaep = 0x0017,
    /// `TPM_ALG_ECDSA`
    Ecdsa = 0x0018,
    /// `TPM_ALG_ECDH`
    Ecdh = 0x0019,
    /// `TPM_ALG_ECDAA`
    Ecdaa = 0x001A,
    /// `TPM_ALG_SM2`
    Sm2 = 0x001B,
    /// `TPM_ALG_ECSCHNORR`
    Eschnorr = 0x001C,
    /// `TPM_ALG_ECMQV`
    Ecmqv = 0x001D,
    /// `TPM_ALG_KDF1_SP800_56A`
    Kdf1Sp800_56A = 0x0020,
    /// `TPM_ALG_KDF2`
    Kdf = 0x0021,
    /// `TPM_ALG_KDF1_SP800_108`
    Kdf1Sp800_180 = 0x0022,
    /// `TPM_ALG_ECC`
    Ecc = 0x0023,
    /// `TPM_ALG_SYMCIPHER`
    SymCipher = 0x0025,
    /// `TPM_ALG_CAMELLIA`
    Camellia = 0x0026,
    /// `TPM_ALG_CTR`
    Ctr = 0x0040,
    /// `TPM_ALG_OFB`
    Ofb = 0x0041,
    /// `TPM_ALG_CBC`
    Cbc = 0x0042,
    /// `TPM_ALG_CFB`
    Cfb = 0x0043,
    /// `TPM_ALG_ECB`
    Ecb = 0x0044,
}

/// `TPM_CC_FIRST`
pub const CC_FIRST: u32 = 0x0000_011F;

/// `TPM_CC_LAST`
pub const CC_LAST: u32 = 0x0000_0193;

/// `TPM_CC`
#[derive(FromRepr, Debug, PartialEq)]
#[repr(u32)]
pub enum TpmCc {
    /// `TPM_CC_CreatePrimary`
    CreatePrimary = 0x0000_0131,
    /// `TPM_CC_DictionaryAttackLockReset`
    DictionaryAttackLockReset = 0x0000_0139,
    /// `TPM_CC_Create`
    Create = 0x0000_0153,
    /// `TPM_CC_Load`
    Load = 0x0000_0157,
    /// `TPM_CC_Unseal`
    Unseal = 0x0000_015E,
    /// `TPM_CC_FlushContext`
    FlushContext = 0x0000_0165,
    /// `TPM_CC_StartAuthSession`
    StartAuthSession = 0x0000_0176,
    /// `TPM_CC_GetCapability`
    GetCapability = 0x0000_017A,
    /// `TPM_CC_GetRandom`
    GetRandom = 0x0000_017B,
    /// `TPM_CC_PCR_Read`
    PcrRead = 0x0000_017E,
    /// `TPM_CC_PolicyPCR`
    PolicyPcr = 0x0000_017F,
    /// `TPM_CC_PCR_Extend`
    PcrExtend = 0x0000_0182,
    /// `TPM_CC_PolicyGetDigest`
    PolicyGetDigest = 0x0000_0189,
    /// `TPM_CC_PolicyPassword`
    PolicyPassword = 0x0000_018C,
}

pub const RC_VER1: u32 = 0x0100;
pub const RC_FMT1: u32 = 0x0080;
pub const RC_WARN: u32 = 0x0900;

#[derive(FromRepr, Debug, PartialEq)]
#[repr(u32)]
pub enum TpmRc {
    Success = 0x0000,
    BadTag = 0x001E,
    Initialize = RC_VER1,
    Failure = RC_VER1 + 0x001,
    Sequence = RC_VER1 + 0x003,
    Private = RC_VER1 + 0x00B,
    Hmac = RC_VER1 + 0x019,
    Disabled = RC_VER1 + 0x020,
    Exclusive = RC_VER1 + 0x021,
    AuthType = RC_VER1 + 0x024,
    AuthMissing = RC_VER1 + 0x025,
    Policy = RC_VER1 + 0x026,
    Pcr = RC_VER1 + 0x027,
    PcrChanged = RC_VER1 + 0x028,
    Upgrade = RC_VER1 + 0x02D,
    TooManyContexts = RC_VER1 + 0x02E,
    AuthUnavailable = RC_VER1 + 0x02F,
    Reboot = RC_VER1 + 0x030,
    Unbalanced = RC_VER1 + 0x031,
    CommandSize = RC_VER1 + 0x042,
    CommandCode = RC_VER1 + 0x043,
    AuthSize = RC_VER1 + 0x044,
    AuthContext = RC_VER1 + 0x045,
    NvRange = RC_VER1 + 0x046,
    NvSize = RC_VER1 + 0x047,
    NvLocked = RC_VER1 + 0x048,
    NvAuthorization = RC_VER1 + 0x049,
    NvUninitialized = RC_VER1 + 0x04A,
    NvSpace = RC_VER1 + 0x04B,
    NvDefined = RC_VER1 + 0x04C,
    BadContext = RC_VER1 + 0x050,
    CpHash = RC_VER1 + 0x051,
    Parent = RC_VER1 + 0x052,
    NeedsTest = RC_VER1 + 0x053,
    NoResult = RC_VER1 + 0x054,
    Sensitive = RC_VER1 + 0x055,
    Asymmetric = RC_FMT1 + 0x001,
    Attributes = RC_FMT1 + 0x002,
    Hash = RC_FMT1 + 0x003,
    Value = RC_FMT1 + 0x004,
    Hierarchy = RC_FMT1 + 0x005,
    KeySize = RC_FMT1 + 0x007,
    Mgf = RC_FMT1 + 0x008,
    Mode = RC_FMT1 + 0x009,
    Type = RC_FMT1 + 0x00A,
    Handle = RC_FMT1 + 0x00B,
    Kdf = RC_FMT1 + 0x00C,
    Range = RC_FMT1 + 0x00D,
    AuthFail = RC_FMT1 + 0x00E,
    Nonce = RC_FMT1 + 0x00F,
    Pp = RC_FMT1 + 0x010,
    Scheme = RC_FMT1 + 0x012,
    Size = RC_FMT1 + 0x015,
    Symmetric = RC_FMT1 + 0x016,
    Tag = RC_FMT1 + 0x017,
    Selector = RC_FMT1 + 0x018,
    Insufficient = RC_FMT1 + 0x01A,
    Signature = RC_FMT1 + 0x01B,
    Key = RC_FMT1 + 0x01C,
    PolicyFail = RC_FMT1 + 0x01D,
    Integrity = RC_FMT1 + 0x01F,
    Ticket = RC_FMT1 + 0x020,
    ReservedBits = RC_FMT1 + 0x021,
    BadAuth = RC_FMT1 + 0x022,
    Expired = RC_FMT1 + 0x023,
    PolicyCc = RC_FMT1 + 0x024,
    Binding = RC_FMT1 + 0x025,
    Curve = RC_FMT1 + 0x026,
    EccPoint = RC_FMT1 + 0x027,
    ContextGap = RC_WARN + 0x001,
    ObjectMemory = RC_WARN + 0x002,
    SessionMemory = RC_WARN + 0x003,
    Memory = RC_WARN + 0x004,
    SessionHandles = RC_WARN + 0x005,
    ObjectHandles = RC_WARN + 0x006,
    Locality = RC_WARN + 0x007,
    Yielded = RC_WARN + 0x008,
    Canceled = RC_WARN + 0x009,
    Testing = RC_WARN + 0x00A,
    ReferenceH0 = RC_WARN + 0x010,
    ReferenceH1 = RC_WARN + 0x011,
    ReferenceH2 = RC_WARN + 0x012,
    ReferenceH3 = RC_WARN + 0x013,
    ReferenceH4 = RC_WARN + 0x014,
    ReferenceH5 = RC_WARN + 0x015,
    ReferenceH6 = RC_WARN + 0x016,
    ReferenceS0 = RC_WARN + 0x018,
    ReferenceS1 = RC_WARN + 0x019,
    ReferenceS2 = RC_WARN + 0x01A,
    ReferenceS3 = RC_WARN + 0x01B,
    ReferenceS4 = RC_WARN + 0x01C,
    ReferenceS5 = RC_WARN + 0x01D,
    ReferenceS6 = RC_WARN + 0x01E,
    NvRate = RC_WARN + 0x020,
    Lockout = RC_WARN + 0x021,
    Retry = RC_WARN + 0x022,
    NvUnavailable = RC_WARN + 0x023,
    NotUsed = RC_WARN + 0x07F,
}

impl From<u32> for TpmRc {
    /// On success, parse `RsponseCode`.
    /// On failure, Return `TpmRc::NotUsed` (`TPM_RC_NOT_USED`) for any
    /// invald response code, as TPM chip should never return that back to the
    /// caller in any legit use case.
    fn from(value: u32) -> TpmRc {
        Self::from_repr(if value & RC_FMT1 != 0 {
            value & (0x3F + RC_FMT1)
        } else if value & RC_WARN != 0 {
            value & (0x7F + RC_WARN)
        } else if value & RC_VER1 != 0 {
            value & (0x7F + RC_VER1)
        } else {
            // RC_VER0
            value & 0x7F
        })
        .unwrap_or(TpmRc::NotUsed)
    }
}

impl fmt::Display for TpmRc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Success => write!(f, "TPM_RC_SUCCESS"),
            Self::BadTag => write!(f, "TPM_RC_BAD_TAG"),
            Self::Initialize => write!(f, "TPM_RC_INITIALIZE"),
            Self::Failure => write!(f, "TPM_RC_FAILURE"),
            Self::Sequence => write!(f, "TPM_RC_SEQUENCE"),
            Self::Private => write!(f, "TPM_RC_PRIVATE"),
            Self::Hmac => write!(f, "TPM_RC_HMAC"),
            Self::Disabled => write!(f, "TPM_RC_DISABLED"),
            Self::Exclusive => write!(f, "TPM_RC_EXCLUSIVE"),
            Self::AuthType => write!(f, "TPM_RC_AUTH_TYPE"),
            Self::AuthMissing => write!(f, "TPM_RC_AUTH_MISSING"),
            Self::Policy => write!(f, "TPM_RC_POLICY"),
            Self::Pcr => write!(f, "TPM_RC_PCR"),
            Self::PcrChanged => write!(f, "TPM_RC_PCR_CHANGED"),
            Self::Upgrade => write!(f, "TPM_RC_UPGRADE"),
            Self::TooManyContexts => write!(f, "TPM_RC_TOO_MANY_CONTEXTS"),
            Self::AuthUnavailable => write!(f, "TPM_RC_AUTH_UNAVAILABLE"),
            Self::Reboot => write!(f, "TPM_RC_REBOOT"),
            Self::Unbalanced => write!(f, "TPM_RC_UNBALANCED"),
            Self::CommandSize => write!(f, "TPM_RC_COMMAND_SIZE"),
            Self::CommandCode => write!(f, "TPM_RC_COMMAND_CODE"),
            Self::AuthSize => write!(f, "TPM_RC_AUTHSIZE"),
            Self::AuthContext => write!(f, "TPM_RC_AUTH_CONTEXT"),
            Self::NvRange => write!(f, "TPM_RC_NV_RANGE"),
            Self::NvSize => write!(f, "TPM_RC_NV_SIZE"),
            Self::NvLocked => write!(f, "TPM_RC_NV_LOCKED"),
            Self::NvAuthorization => write!(f, "TPM_RC_NV_AUTHORIZATION"),
            Self::NvUninitialized => write!(f, "TPM_RC_NV_UNINITIALIZED"),
            Self::NvSpace => write!(f, "TPM_RC_NV_SPACE"),
            Self::NvDefined => write!(f, "TPM_RC_NV_DEFINED"),
            Self::BadContext => write!(f, "TPM_RC_BAD_CONTEXT"),
            Self::CpHash => write!(f, "TPM_RC_CPHASH"),
            Self::Parent => write!(f, "TPM_RC_PARENT"),
            Self::NeedsTest => write!(f, "TPM_RC_NEEDS_TEST"),
            Self::NoResult => write!(f, "TPM_RC_NO_RESULT"),
            Self::Sensitive => write!(f, "TPM_RC_SENSITIVE"),
            Self::Asymmetric => write!(f, "TPM_RC_ASYMMETRIC"),
            Self::Attributes => write!(f, "TPM_RC_ATTRIBUTES"),
            Self::Hash => write!(f, "TPM_RC_HASH"),
            Self::Value => write!(f, "TPM_RC_VALUE"),
            Self::Hierarchy => write!(f, "TPM_RC_HIERARCHY"),
            Self::KeySize => write!(f, "TPM_RC_KEY_SIZE"),
            Self::Mgf => write!(f, "TPM_RC_MGF"),
            Self::Mode => write!(f, "TPM_RC_MODE"),
            Self::Type => write!(f, "TPM_RC_TYPE"),
            Self::Handle => write!(f, "TPM_RC_HANDLE"),
            Self::Kdf => write!(f, "TPM_RC_KDF"),
            Self::Range => write!(f, "TPM_RC_RANGE"),
            Self::AuthFail => write!(f, "TPM_RC_AUTH_FAIL"),
            Self::Nonce => write!(f, "TPM_RC_NONCE"),
            Self::Pp => write!(f, "TPM_RC_PP"),
            Self::Scheme => write!(f, "TPM_RC_SCHEME"),
            Self::Size => write!(f, "TPM_RC_SIZE"),
            Self::Symmetric => write!(f, "TPM_RC_SYMMETRIC"),
            Self::Tag => write!(f, "TPM_RC_TAG"),
            Self::Selector => write!(f, "TPM_RC_SELECTOR"),
            Self::Insufficient => write!(f, "TPM_RC_INSUFFICIENT"),
            Self::Signature => write!(f, "TPM_RC_SIGNATURE"),
            Self::Key => write!(f, "TPM_RC_KEY"),
            Self::PolicyFail => write!(f, "TPM_RC_POLICY_FAIL"),
            Self::Integrity => write!(f, "TPM_RC_INTEGRITY"),
            Self::Ticket => write!(f, "TPM_RC_TICKET"),
            Self::ReservedBits => write!(f, "TPM_RC_RESERVED_BITS"),
            Self::BadAuth => write!(f, "TPM_RC_BAD_AUTH"),
            Self::Expired => write!(f, "TPM_RC_EXPIRED"),
            Self::PolicyCc => write!(f, "TPM_RC_POLICY_CC"),
            Self::Binding => write!(f, "TPM_RC_BINDING"),
            Self::Curve => write!(f, "TPM_RC_CURVE"),
            Self::EccPoint => write!(f, "TPM_RC_ECC_POINT"),
            Self::ContextGap => write!(f, "TPM_RC_CONTEXT_GAP"),
            Self::ObjectMemory => write!(f, "TPM_RC_OBJECT_MEMORY"),
            Self::SessionMemory => write!(f, "TPM_RC_SESSION_MEMORY"),
            Self::Memory => write!(f, "TPM_RC_MEMORY"),
            Self::SessionHandles => write!(f, "TPM_RC_SESSION_HANDLES"),
            Self::ObjectHandles => write!(f, "TPM_RC_OBJECT_HANDLES"),
            Self::Locality => write!(f, "TPM_RC_LOCALITY"),
            Self::Yielded => write!(f, "TPM_RC_YIELDED"),
            Self::Canceled => write!(f, "TPM_RC_CANCELED"),
            Self::Testing => write!(f, "TPM_RC_TESTING"),
            Self::ReferenceH0 => write!(f, "TPM_RC_REFERENCE_H0"),
            Self::ReferenceH1 => write!(f, "TPM_RC_REFERENCE_H1"),
            Self::ReferenceH2 => write!(f, "TPM_RC_REFERENCE_H2"),
            Self::ReferenceH3 => write!(f, "TPM_RC_REFERENCE_H3"),
            Self::ReferenceH4 => write!(f, "TPM_RC_REFERENCE_H4"),
            Self::ReferenceH5 => write!(f, "TPM_RC_REFERENCE_H5"),
            Self::ReferenceH6 => write!(f, "TPM_RC_REFERENCE_H6"),
            Self::ReferenceS0 => write!(f, "TPM_RC_REFERENCE_S0"),
            Self::ReferenceS1 => write!(f, "TPM_RC_REFERENCE_S1"),
            Self::ReferenceS2 => write!(f, "TPM_RC_REFERENCE_S2"),
            Self::ReferenceS3 => write!(f, "TPM_RC_REFERENCE_S3"),
            Self::ReferenceS4 => write!(f, "TPM_RC_REFERENCE_S4"),
            Self::ReferenceS5 => write!(f, "TPM_RC_REFERENCE_S5"),
            Self::ReferenceS6 => write!(f, "TPM_RC_REFERENCE_S6"),
            Self::NvRate => write!(f, "TPM_RC_NV_RATE"),
            Self::Lockout => write!(f, "TPM_RC_LOCKOUT"),
            Self::Retry => write!(f, "TPM_RC_RETRY"),
            Self::NvUnavailable => write!(f, "TPM_RC_NV_UNAVAILABLE"),
            Self::NotUsed => write!(f, "TPM_RC_NOT_USED"),
        }
    }
}

/// `TPM_ST`
#[derive(FromRepr, Debug, PartialEq)]
#[repr(u16)]
pub enum TpmTag {
    /// `TPM_ST_RSP_COMMAND`
    RspCommand = 0x00C4,
    /// `TPM_ST_NULL`
    Null = 0x8000,
    /// `TPM_ST_NO_SESSIONS`
    NoSessions = 0x8001,
    /// `TPM_ST_SESSIONS`
    Sessions = 0x8002,
    /// `TPM_ST_ATTEST_NV`
    AttestNv = 0x8014,
    /// `TPM_ST_ATTEST_COMMAND_AUDIT`
    AttestCommandAudit = 0x8015,
    /// `TPM_ST_ATTEST_SESSION_AUDIT`
    AttestSessionAudit = 0x8016,
    /// `TPM_ST_ATTEST_CERTIFY`
    AttesCertify = 0x8017,
    /// `TPM_ST_ATTEST_QUOTE`
    AttestQuote = 0x8018,
    /// `TPM_ST_ATTEST_TIME`
    AttestTime = 0x8019,
    /// `TPM_ST_ATTEST_CREATION`
    AttestCreation = 0x801A,
    /// `TPM_ST_CREATION`
    Creation = 0x8021,
    /// `TPM_ST_VERIFIED`
    Verified = 0x8022,
    /// `TPM_ST_AUTH_SECRET`
    AuthSecret = 0x8023,
    /// `TPM_ST_HASHCHECK`
    HashCheck = 0x0024,
    /// `TPM_ST_AUTH_SIGNED`
    AuthSigned = 0x0025,
    /// `TPM_ST_FU_MANIFEST`: a structure describing a Field Upgrade Policy
    FuManifest = 0x0029,
}

/// `TPM_CAP_LAST`
pub const CAP_LAST: u32 = 0x0000_0009;

/// `TPM_CAP_VENDOR_PROPERTY`: manufacturer-specific
pub const CAP_VENDOR_PROPERTY: u32 = 0x0000_0100;

/// `TPM_SE`
#[derive(FromRepr, Debug, PartialEq)]
#[repr(u8)]
pub enum TpmSession {
    /// `TPM_SE_HMAC`
    Hmac = 0x00,
    /// `TPM_SE_POLICY`
    Policy = 0x01,
    /// `TPM_SE_TRIAL`
    Trial = 0x03,
}

/// `TPM_CAP`
#[derive(FromRepr, Debug, PartialEq)]
#[repr(u32)]
pub enum TpmCap {
    /// `TPM_CAP_ALGS`
    Algs = 0x0000_0000,
    /// `TPM_CAP_HANDLES`
    Handles = 0x0000_0001,
    /// `TPM_CAP_COMMANDS`
    Commands = 0x0000_0002,
    /// `TPM_CAP_PP_COMMANDS`
    PpCommands = 0x0000_0003,
    /// `TPM_CAP_AUDIT_COMMANDS`
    AuditCommands = 0x0000_0004,
    /// `TPM_CAP_PCRS`
    Pcrs = 0x0000_0005,
    /// `TPM_CAP_TPM_PROPERTIES`
    TpmProperties = 0x0000_0006,
    /// `TPM_CAP_PCR_PROPERTIES`
    PcrProperties = 0x0000_0007,
    /// `TPM_CAP_ECC_CURVES`
    EccCurves = 0x0000_0008,
    /// `TPM_CAP_AUTH_POLICIES`
    AuthPolicies = 0x0000_0009,
}

/// `TPM_HT`
#[derive(FromRepr, Debug, PartialEq)]
#[repr(u8)]
pub enum TpmClass {
    /// `TPM_HT_PCR`
    Pcr = 0x00,
    /// `TPM_HT_NV_INDEX`
    NvIndex = 0x01,
    /// `TPM_HT_HMAC_SESSION` and `TPM_HT_LOADED_SESSION`
    HmacSession = 0x02,
    /// `TPM_HT_POLICY_SESSION` and `TPM_HT_SAVED_SESSION`
    PolicySession = 0x03,
    /// `TPM_HT_PERMANENT`
    Permanent = 0x40,
    /// `TPM_HT_TRANSIENT`
    Transient = 0x80,
    /// `TPM_HT_PERSISTENT`
    Persistent = 0x81,
}

/// `TPM_HT`
#[derive(FromRepr, Debug, PartialEq)]
#[repr(u32)]
pub enum TpmHandle {
    /// `TPM_RH_FIRST`
    NotUsed = 0x4000_0000,
    /// `TPM_RH_OWNER`
    Owner = 0x4000_0001,
    /// `TPM_RH_NULL`
    Null = 0x4000_0007,
    /// `TPM_RH_UNASSIGNED`
    Unassigned = 0x4000_0008,
    /// `TPM_RS_PW`
    Password = 0x4000_0009,
    /// `TPM_RH_LOCKOUT`
    Lockout = 0x4000_000A,
    /// `TPM_RH_ENDORSEMENT`
    Endorsement = 0x4000_000B,
    /// `TPM_RH_PLATFORM`
    Platform = 0x4000_000C,
    /// `TPM_RH_PLATFORM_NV`
    PlatformNv = 0x4000_000D,
    /// `TPM_RH_AUTH_00`
    Auth00 = 0x4000_0010,
    /// `TPM_RH_AUTH_FF`
    AuthFF = 0x4000_010F,
    /// The first transient handle
    Transient = 0x8000_0000,
    /// The first persistent handle
    Persistent = 0x8100_0000,
}

bitflags! {
    /// `TPMA_OBJECT`
    pub struct TpmObject : u32 {
        /// Not used
        const NotUsed = 0x0000_0001;
        /// Hierarchy is immutable
        const FixedTPM = 0x0000_0002;
        /// TPM chip reset invalidates also saved contexts
        const StClear = 0x0000_0004;
        /// Parent is immutable
        const FixedParent = 0x0000_0010;
        /// TPM-only generated secrets
        const SensitiveDataOrigin = 0x0000_0020;
        /// Allow user access without policy session
        const UserWithAuth = 0x0000_0040;
        /// Deny admin access without policy session
        const AdminWithPolicy = 0x0000_0080;
        /// Deny dictionary attack protections
        const NoDa = 0x0000_0400;
        /// Encrypted duplication
        const EncryptedDuplication = 0x0000_0800;
        /// Manipulate only structures of known format
        const Restricted = 0x0001_0000;
        /// Decrypt with the private key
        const Decrypt = 0x0002_0000;
        /// Decrypt with the private key
        const Encrypt = 0x0004_0000;
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[repr(C, align(2))]
pub struct TpmHeader {
    tag: u16,
    size: u32,
    code: u32,
}

impl TpmHeader {
    /// Creates a new instance
    #[must_use]
    pub const fn new(tag: TpmTag, size: u32, code: TpmCc) -> Self {
        let tag = tag as u16;
        let code = code as u32;
        Self { tag, size, code }
    }
}

/// `TPM2_GetCapability`
///
/// # Errors
///
/// Can fail when read or write operation returns corrupted data or out of
/// memory.
pub fn tpm2_get_capability<T>(
    file: &mut T,
    property: u32,
    property_count: u32,
    handles: &mut Vec<u32>,
) -> Result<()>
where
    T: Read + Write,
{
    // Write command to the TPM chip.
    let mut buf = vec![];
    buf.extend((TpmTag::NoSessions as u16).to_be_bytes());
    buf.extend((22_u32).to_be_bytes());
    buf.extend((TpmCc::GetCapability as u32).to_be_bytes());
    buf.extend((TpmCap::Handles as u32).to_be_bytes());
    buf.extend(property.to_be_bytes());
    buf.extend(property_count.to_be_bytes());
    file.write_all(&buf)?;
    // Read response from the TPM chip.
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    // Check that the static part of the header for `TPM2_GetCapability` takes
    // exactly 19 bytes and the tail should be a multiple of the handle size. If
    // these conditions are not met, the data will be corrupted.
    if buf.len() < 19 || ((buf.len() - 19) & 0x03) != 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    let response_size: usize = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
    // Check that the response header contains matching size with the total size
    // of the received data.
    if response_size != buf.len() {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    let handles_count = u32::from_be_bytes([buf[15], buf[16], buf[17], buf[18]]) as usize;
    if handles_count != ((buf.len() - 19) >> 2) {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if handles_count > property_count as usize {
        return Err(Error::from(ErrorKind::OutOfMemory));
    }
    for i in 0..handles_count {
        let j: usize = i + 19;
        let handle = u32::from_be_bytes([buf[j], buf[j + 1], buf[j + 2], buf[j + 3]]);
        handles.push(handle);
    }
    Ok(())
}
