// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#[allow(unused_imports)]
use crate::{tpm_enum, TpmErrorKind, TpmNotDiscriminant, TpmParse};
use core::{
    convert::TryFrom,
    fmt::{self, Debug, Display, Formatter},
};

pub const TPM_RC_VER1: u32 = 0x0100;
pub const TPM_RC_FMT1: u32 = 0x0080;
pub const TPM_RC_WARN: u32 = 0x0900;
pub const TPM_RC_P_BIT: u32 = 1 << 6;
pub const TPM_RC_N_SHIFT: u32 = 8;
pub const TPM_RC_FMT1_ERROR_MASK: u32 = 0x003F;

const MAX_HANDLE_INDEX: u8 = 7;
const SESSION_INDEX_OFFSET: u8 = 8;

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

/// Extracts the base response code from a raw `u32` value.
fn get_base_code(value: u32) -> u32 {
    if (value & TPM_RC_FMT1) != 0 {
        TPM_RC_FMT1 | (value & TPM_RC_FMT1_ERROR_MASK)
    } else {
        value
    }
}

#[must_use]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct TpmRc(u32);
impl TpmRc {
    /// Returns the base error code, with handle, parameter, or session index
    /// stripped out.
    ///
    /// # Errors
    ///
    /// Returns a `TpmErrorKind::InternalError` on error, as the error case
    /// should be unreachable.
    pub fn base(self) -> Result<TpmRcBase, TpmErrorKind> {
        TpmRcBase::try_from(get_base_code(self.0)).map_err(|()| TpmErrorKind::InternalError)
    }

    #[must_use]
    pub fn index(self) -> Option<TpmRcIndex> {
        let value = self.0;
        if (value & TPM_RC_FMT1) == 0 {
            return None;
        }
        let is_parameter = (value & TPM_RC_P_BIT) != 0;
        let n = ((value >> TPM_RC_N_SHIFT) & 0b1111) as u8;

        match (is_parameter, n) {
            (_, 0) => None,
            (true, num) => Some(TpmRcIndex::Parameter(num)),
            (false, num @ 1..=MAX_HANDLE_INDEX) => Some(TpmRcIndex::Handle(num)),
            (false, num) => Some(TpmRcIndex::Session(num - SESSION_INDEX_OFFSET)),
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

impl crate::TpmParse for TpmRc {
    fn parse(buf: &[u8]) -> crate::TpmResult<(Self, &[u8])> {
        let (val, remainder) = u32::parse(buf)?;
        let rc = Self::try_from(val)?;
        Ok((rc, remainder))
    }
}

impl TryFrom<u32> for TpmRc {
    type Error = TpmErrorKind;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let base_code = get_base_code(value);
        TpmRcBase::try_from(base_code).map_err(|()| {
            TpmErrorKind::NotDiscriminant(
                "TpmRcBase",
                TpmNotDiscriminant::Unsigned(u64::from(base_code)),
            )
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
