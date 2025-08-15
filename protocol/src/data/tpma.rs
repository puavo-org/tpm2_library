// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

use crate::tpm_bitflags;

tpm_bitflags! {
    /// `TPMA_ALGORITHM`
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TpmaAlgorithm(u32) {
        const ASYMMETRIC = 0x0000_0001, "ASYMMETRIC";
        const SYMMETRIC = 0x0000_0002, "SYMMETRIC";
        const HASH = 0x0000_0004, "HASH";
        const OBJECT = 0x0000_0008, "OBJECT";
        const SIGNING = 0x0000_0100, "SIGNING";
        const ENCRYPTING = 0x0000_0200, "ENCRYPTING";
        const METHOD = 0x0000_0400, "METHOD";
    }
}

tpm_bitflags! {
    /// `TPMA_LOCALITY` (Table 41)
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TpmaLocality(u8) {
        const TPM_LOC_ZERO = 0x01, "LOC_ZERO";
        const TPM_LOC_ONE = 0x02, "LOC_ONE";
        const TPM_LOC_TWO = 0x04, "LOC_TWO";
        const TPM_LOC_THREE = 0x08, "LOC_THREE";
        const TPM_LOC_FOUR = 0x10, "LOC_FOUR";
        const EXTENDED = 0xE0, "EXTENDED";
    }
}

tpm_bitflags! {
    /// `TPMA_NV` (Table 233)
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TpmaNv(u32) {
        const PPWRITE = 0x0000_0001, "PPWRITE";
        const OWNERWRITE = 0x0000_0002, "OWNERWRITE";
        const AUTHWRITE = 0x0000_0004, "AUTHWRITE";
        const POLICYWRITE = 0x0000_0008, "POLICYWRITE";
        const TPM_NT_COUNTER = 0x0000_0010, "COUNTER";
        const TPM_NT_BITS = 0x0000_0020, "BITS";
        const TPM_NT_EXTEND = 0x0000_0040, "EXTEND";
        const POLICY_DELETE = 0x0000_0400, "POLICY_DELETE";
        const WRITELOCKED = 0x0000_0800, "WRITELOCKED";
        const WRITEALL = 0x0000_1000, "WRITEALL";
        const WRITEDEFINE = 0x0000_2000, "WRITEDEFINE";
        const WRITE_STCLEAR = 0x0000_4000, "WRITE_STCLEAR";
        const GLOBALLOCK = 0x0000_8000, "GLOBALLOCK";
        const PPREAD = 0x0001_0000, "PPREAD";
        const OWNERREAD = 0x0002_0000, "OWNERREAD";
        const AUTHREAD = 0x0004_0000, "AUTHREAD";
        const POLICYREAD = 0x0008_0000, "POLICYREAD";
        const NO_DA = 0x0200_0000, "NO_DA";
        const ORDERLY = 0x0400_0000, "ORDERLY";
        const CLEAR_STCLEAR = 0x0800_0000, "CLEAR_STCLEAR";
        const READLOCKED = 0x1000_0000, "READLOCKED";
        const WRITTEN = 0x2000_0000, "WRITTEN";
        const PLATFORMCREATE = 0x4000_0000, "PLATFORMCREATE";
        const READ_STCLEAR = 0x8000_0000, "READ_STCLEAR";
    }
}

tpm_bitflags! {
    /// `TPMA_OBJECT`
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TpmaObject(u32) {
        const FIXED_TPM = 0x0000_0002, "FIXED_TPM";
        const ST_CLEAR = 0x0000_0004, "ST_CLEAR";
        const FIXED_PARENT = 0x0000_0010, "FIXED_PARENT";
        const SENSITIVE_DATA_ORIGIN = 0x0000_0020, "SENSITIVE_DATA_ORIGIN";
        const USER_WITH_AUTH = 0x0000_0040, "USER_WITH_AUTH";
        const ADMIN_WITH_POLICY = 0x0000_0080, "ADMIN_WITH_POLICY";
        const NO_DA = 0x0000_0400, "NO_DA";
        const ENCRYPTED_DUPLICATION = 0x0000_0800, "ENCRYPTED_DUPLICATION";
        const RESTRICTED = 0x0001_0000, "RESTRICTED";
        const DECRYPT = 0x0002_0000, "DECRYPT";
        const SIGN_ENCRYPT = 0x0004_0000, "SIGN_ENCRYPT";
    }
}

tpm_bitflags! {
    /// `TPMA_SESSION`
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TpmaSession(u8) {
        const CONTINUE_SESSION = 0x01, "CONTINUE_SESSION";
        const AUDIT_EXCLUSIVE = 0x02, "AUDIT_EXCLUSIVE";
        const AUDIT_RESET = 0x04, "AUDIT_RESET";
        const DECRYPT = 0x20, "DECRYPT";
        const ENCRYPT = 0x40, "ENCRYPT";
        const AUDIT = 0x80, "AUDIT";
    }
}
