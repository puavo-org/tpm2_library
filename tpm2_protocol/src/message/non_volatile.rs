// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 23 Non-Volatile (NV) Storage

use crate::{
    data::{
        Tpm2bAttest, Tpm2bAuth, Tpm2bData, Tpm2bMaxNvBuffer, Tpm2bName, Tpm2bNvPublic, TpmCc,
        TpmtSignature,
    },
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvDefineSpaceCommand,
    TpmCc::NvDefineSpace,
    false,
    true,
    1,
    {
        pub auth: Tpm2bAuth,
        pub public_info: Tpm2bNvPublic,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvDefineSpaceResponse,
    TpmCc::NvDefineSpace,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmNvUndefineSpaceCommand,
    TpmCc::NvUndefineSpace,
    false,
    true,
    2,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvUndefineSpaceResponse,
    TpmCc::NvUndefineSpace,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmNvUndefineSpaceSpecialCommand,
    TpmCc::NvUndefineSpaceSpecial,
    false,
    true,
    2,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvUndefineSpaceSpecialResponse,
    TpmCc::NvUndefineSpaceSpecial,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmNvReadPublicCommand,
    TpmCc::NvReadPublic,
    true,
    false,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvReadPublicResponse,
    TpmCc::NvReadPublic,
    true,
    false,
    0,
    {
        pub nv_public: Tpm2bNvPublic,
        pub nv_name: Tpm2bName,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvWriteCommand,
    TpmCc::NvWrite,
    false,
    true,
    2,
    {
        pub data: Tpm2bMaxNvBuffer,
        pub offset: u16,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvWriteResponse,
    TpmCc::NvWrite,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvIncrementCommand,
    TpmCc::NvIncrement,
    false,
    true,
    2,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvIncrementResponse,
    TpmCc::NvIncrement,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvExtendCommand,
    TpmCc::NvExtend,
    false,
    true,
    2,
    {
        pub data: Tpm2bMaxNvBuffer,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvExtendResponse,
    TpmCc::NvExtend,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmNvSetBitsCommand,
    TpmCc::NvSetBits,
    false,
    true,
    2,
    {
        pub bits: u64,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvSetBitsResponse,
    TpmCc::NvSetBits,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvWriteLockCommand,
    TpmCc::NvWriteLock,
    false,
    true,
    2,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvWriteLockResponse,
    TpmCc::NvWriteLock,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvGlobalWriteLockCommand,
    TpmCc::NvGlobalWriteLock,
    false,
    true,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvGlobalWriteLockResponse,
    TpmCc::NvGlobalWriteLock,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmNvReadCommand,
    TpmCc::NvRead,
    false,
    true,
    2,
    {
        pub size: u16,
        pub offset: u16,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmNvReadResponse,
    TpmCc::NvRead,
    false,
    true,
    0,
    {
        pub data: Tpm2bMaxNvBuffer,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvReadLockCommand,
    TpmCc::NvReadLock,
    false,
    true,
    2,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvReadLockResponse,
    TpmCc::NvReadLock,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvChangeAuthCommand,
    TpmCc::NvChangeAuth,
    false,
    true,
    1,
    {
        pub new_auth: Tpm2bAuth,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvChangeAuthResponse,
    TpmCc::NvChangeAuth,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvCertifyCommand,
    TpmCc::NvCertify,
    false,
    true,
    3,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
        pub size: u16,
        pub offset: u16,
    }
);

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvCertifyResponse,
    TpmCc::NvCertify,
    false,
    true,
    0,
    {
        pub certify_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}
