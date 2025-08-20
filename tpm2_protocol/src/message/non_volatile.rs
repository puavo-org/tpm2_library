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

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmNvDefineSpaceCommand,
    cc: TpmCc::NvDefineSpace,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub auth: Tpm2bAuth,
        pub public_info: Tpm2bNvPublic,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvDefineSpaceResponse,
    cc: TpmCc::NvDefineSpace,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvUndefineSpaceCommand,
    cc: TpmCc::NvUndefineSpace,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
        pub nv_index: u32,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvUndefineSpaceResponse,
    cc: TpmCc::NvUndefineSpace,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvUndefineSpaceSpecialCommand,
    cc: TpmCc::NvUndefineSpaceSpecial,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub nv_index: u32,
        pub platform: crate::data::TpmiRhHierarchy,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvUndefineSpaceSpecialResponse,
    cc: TpmCc::NvUndefineSpaceSpecial,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvReadPublicCommand,
    cc: TpmCc::NvReadPublic,
    no_sessions: true,
    with_sessions: false,
    handles: {
        pub nv_index: u32,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmNvReadPublicResponse,
    cc: TpmCc::NvReadPublic,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub nv_public: Tpm2bNvPublic,
        pub nv_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmNvWriteCommand,
    cc: TpmCc::NvWrite,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiDhObject,
        pub nv_index: u32,
    },
    parameters: {
        pub data: Tpm2bMaxNvBuffer,
        pub offset: u16,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvWriteResponse,
    cc: TpmCc::NvWrite,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvIncrementCommand,
    cc: TpmCc::NvIncrement,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiDhObject,
        pub nv_index: u32,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvIncrementResponse,
    cc: TpmCc::NvIncrement,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmNvExtendCommand,
    cc: TpmCc::NvExtend,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiDhObject,
        pub nv_index: u32,
    },
    parameters: {
        pub data: Tpm2bMaxNvBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvExtendResponse,
    cc: TpmCc::NvExtend,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvSetBitsCommand,
    cc: TpmCc::NvSetBits,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiDhObject,
        pub nv_index: u32,
    },
    parameters: {
        pub bits: u64,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvSetBitsResponse,
    cc: TpmCc::NvSetBits,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvWriteLockCommand,
    cc: TpmCc::NvWriteLock,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiDhObject,
        pub nv_index: u32,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvWriteLockResponse,
    cc: TpmCc::NvWriteLock,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvGlobalWriteLockCommand,
    cc: TpmCc::NvGlobalWriteLock,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvGlobalWriteLockResponse,
    cc: TpmCc::NvGlobalWriteLock,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvReadCommand,
    cc: TpmCc::NvRead,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiDhObject,
        pub nv_index: u32,
    },
    parameters: {
        pub size: u16,
        pub offset: u16,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmNvReadResponse,
    cc: TpmCc::NvRead,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {
        pub data: Tpm2bMaxNvBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvReadLockCommand,
    cc: TpmCc::NvReadLock,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiDhObject,
        pub nv_index: u32,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvReadLockResponse,
    cc: TpmCc::NvReadLock,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmNvChangeAuthCommand,
    cc: TpmCc::NvChangeAuth,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub nv_index: u32,
    },
    parameters: {
        pub new_auth: Tpm2bAuth,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvChangeAuthResponse,
    cc: TpmCc::NvChangeAuth,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmNvCertifyCommand,
    cc: TpmCc::NvCertify,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub sign_handle: crate::data::TpmiDhObject,
        pub auth_handle: crate::data::TpmiDhObject,
        pub nv_index: u32,
    },
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
        pub size: u16,
        pub offset: u16,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmNvCertifyResponse,
    cc: TpmCc::NvCertify,
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
    name: TpmNvDefineSpace2Command,
    cc: TpmCc::NvDefineSpace2,
    no_sessions: false,
    with_sessions: true,
    handles: {
        pub auth_handle: crate::data::TpmiRhHierarchy,
    },
    parameters: {
        pub auth: Tpm2bAuth,
        pub public_info: crate::data::Tpm2bNvPublic2,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvDefineSpace2Response,
    cc: TpmCc::NvDefineSpace2,
    no_sessions: false,
    with_sessions: true,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvReadPublic2Command,
    cc: TpmCc::NvReadPublic2,
    no_sessions: true,
    with_sessions: false,
    handles: {
        pub nv_index: u32,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmNvReadPublic2Response,
    cc: TpmCc::NvReadPublic2,
    no_sessions: true,
    with_sessions: false,
    handles: {},
    parameters: {
        pub nv_public: crate::data::Tpm2bNvPublic2,
        pub nv_name: Tpm2bName,
    }
}
