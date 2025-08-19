// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::tpm_enum;

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
    pub enum TpmAt(u32) {
        (Any, 0x0000_0000, "TPM_AT_ANY"),
        (Error, 0x0000_0001, "TPM_AT_ERROR"),
        (Pv1, 0x0000_0002, "TPM_AT_PV1"),
        (Vend, 0x8000_0000, "TPM_AT_VEND"),
    }
}

impl Default for TpmAt {
    fn default() -> Self {
        Self::Any
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
        (NvChangeAuth, 0x0000_013B, "TPM_CC_NV_ChangeAuth"),
        (PcrEvent, 0x0000_013C, "TPM_CC_PCR_Event"),
        (PcrReset, 0x0000_013D, "TPM_CC_PCR_Reset"),
        (SequenceComplete, 0x0000_013E, "TPM_CC_SequenceComplete"),
        (FieldUpgradeData, 0x0000_0141, "TPM_CC_FieldUpgradeData"),
        (IncrementalSelfTest, 0x0000_0142, "TPM_CC_IncrementalSelfTest"),
        (SelfTest, 0x0000_0143, "TPM_CC_SelfTest"),
        (Startup, 0x0000_0144, "TPM_CC_Startup"),
        (Shutdown, 0x0000_0145, "TPM_CC_Shutdown"),
        (StirRandom, 0x0000_0146, "TPM_CC_StirRandom"),
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
        (EcdhZGen, 0x0000_0154, "TPM_CC_ECDH_ZGen"),
        (ZGen2Phase, 0x0000_0155, "TPM_CC_ZGen_2Phase"),
        (Import, 0x0000_0156, "TPM_CC_Import"),
        (Load, 0x0000_0157, "TPM_CC_Load"),
        (Quote, 0x0000_0158, "TPM_CC_Quote"),
        (RsaDecrypt, 0x0000_0159, "TPM_CC_RSA_Decrypt"),
        (EccEncrypt, 0x0000_015A, "TPM_CC_ECC_Encrypt"),
        (EccDecrypt, 0x0000_015B, "TPM_CC_ECC_Decrypt"),
        (SequenceUpdate, 0x0000_015C, "TPM_CC_SequenceUpdate"),
        (Sign, 0x0000_015D, "TPM_CC_Sign"),
        (Unseal, 0x0000_015E, "TPM_CC_Unseal"),
        (PolicySigned, 0x0000_0160, "TPM_CC_PolicySigned"),
        (ContextLoad, 0x0000_0161, "TPM_CC_ContextLoad"),
        (ContextSave, 0x0000_0162, "TPM_CC_ContextSave"),
        (EcdhKeyGen, 0x0000_0163, "TPM_CC_ECDH_KeyGen"),
        (FlushContext, 0x0000_0165, "TPM_CC_FlushContext"),
        (LoadExternal, 0x0000_0167, "TPM_CC_LoadExternal"),
        (MakeCredential, 0x0000_0168, "TPM_CC_MakeCredential"),
        (NvReadPublic, 0x0000_0169, "TPM_CC_NV_ReadPublic"),
        (PolicyAuthValue, 0x0000_016B, "TPM_CC_PolicyAuthValue"),
        (PolicyCommandCode, 0x0000_016C, "TPM_CC_PolicyCommandCode"),
        (PolicyCpHash, 0x0000_016E, "TPM_CC_PolicyCpHash"),
        (PolicyLocality, 0x0000_016F, "TPM_CC_PolicyLocality"),
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
        (PolicyGetDigest, 0x0000_0189, "TPM_CC_PolicyGetDigest"),
        (PolicyPassword, 0x0000_018C, "TPM_CC_PolicyPassword"),
        (EncryptDecrypt2, 0x0000_0193, "TPM_CC_EncryptDecrypt2"),
        (AcGetCapability, 0x0000_0194, "TPM_CC_AcGetCapability"),
        (AcSend, 0x0000_0195, "TPM_CC_AcSend"),
        (PolicyAcSendSelect, 0x0000_0196, "TPM_CC_Policy_AC_SendSelect"),
        (ActSetTimeout, 0x0000_0198, "TPM2_ACT_SetTimeout"),
        (NvDefineSpace2, 0x0000_019D, "TPM_CC_NV_DefineSpace2"),
        (NvReadPublic2, 0x0000_019E, "TPM_CC_NV_ReadPublic2"),
        (VendorTcgTest, 0x2000_0000, "TPM_CC_Vendor_TCG_Test"),
    }
}

tpm_enum! {
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Default)]
    pub enum TpmClockAdjust(i8) {
        (CoarseSlower, -3, "TPM_CLOCK_COARSE_SLOWER"),
        (MediumSlower, -2, "TPM_CLOCK_MEDIUM_SLOWER"),
        (FineSlower, -1, "TPM_CLOCK_FINE_SLOWER"),
        #[default]
        (NoChange, 0, "TPM_CLOCK_NO_CHANGE"),
        (FineFaster, 1, "TPM_CLOCK_FINE_FASTER"),
        (MediumFaster, 2, "TPM_CLOCK_MEDIUM_FASTER"),
        (CoarseFaster, 3, "TPM_CLOCK_COARSE_FASTER"),
    }
}

tpm_enum! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    pub enum TpmEccCurve(u16) {
        #[default]
        (None, 0x0000, "TPM_ECC_NONE"),
        (NistP192, 0x0001, "TPM_ECC_NIST_P192"),
        (NistP224, 0x0002, "TPM_ECC_NIST_P224"),
        (NistP256, 0x0003, "TPM_ECC_NIST_P256"),
        (NistP384, 0x0004, "TPM_ECC_NIST_P384"),
        (NistP521, 0x0005, "TPM_ECC_NIST_P521"),
    }
}

tpm_enum! {
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Default)]
    pub enum TpmiEccKeyExchange(u16) {
        #[default]
        (None, 0x0000, "TPM_ECC_NONE"),
        (Ecdh, 0x0019, "TPM_ALG_ECDH"),
        (Ecmqv, 0x001D, "TPM_ALG_ECMQV"),
        (Sm2, 0x001B, "TPM_ALG_SM2"),
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
