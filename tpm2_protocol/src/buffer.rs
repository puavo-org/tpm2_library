// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{build_tpm2b, parse_tpm2b, TpmBuild, TpmErrorKind, TpmParse, TpmResult, TpmSized};
use core::{convert::TryFrom, fmt::Debug, mem::size_of, ops::Deref};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmBuffer<const CAPACITY: usize> {
    bytes: [u8; CAPACITY],
    len: usize,
}

impl<const CAPACITY: usize> TpmBuffer<CAPACITY> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            len: 0,
        }
    }
}

impl<const CAPACITY: usize> Deref for TpmBuffer<CAPACITY> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes[..self.len]
    }
}

impl<const CAPACITY: usize> Default for TpmBuffer<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> TpmSized for TpmBuffer<CAPACITY> {
    const SIZE: usize = size_of::<u16>() + CAPACITY;
    fn len(&self) -> usize {
        size_of::<u16>() + self.len
    }
}

impl<const CAPACITY: usize> TpmBuild for TpmBuffer<CAPACITY> {
    fn build(&self, writer: &mut crate::TpmWriter) -> TpmResult<()> {
        build_tpm2b(writer, self)
    }
}

impl<const CAPACITY: usize> TpmParse for TpmBuffer<CAPACITY> {
    fn parse(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (bytes, remainder) = parse_tpm2b(buf)?;
        let buffer = Self::try_from(bytes)?;
        Ok((buffer, remainder))
    }
}

impl<const CAPACITY: usize> TryFrom<&[u8]> for TpmBuffer<CAPACITY> {
    type Error = TpmErrorKind;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() > CAPACITY {
            return Err(TpmErrorKind::CapacityExceeded);
        }
        let mut buffer = Self::new();
        buffer.bytes[..slice.len()].copy_from_slice(slice);
        buffer.len = slice.len();
        Ok(buffer)
    }
}

impl<const CAPACITY: usize> AsRef<[u8]> for TpmBuffer<CAPACITY> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<const CAPACITY: usize> Debug for TpmBuffer<CAPACITY> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TpmBuffer(")?;
        if let Some(first) = self.first() {
            write!(f, "{first:02X}")?;
            for byte in self.iter().skip(1) {
                write!(f, " {byte:02X}")?;
            }
        }
        write!(f, ")")
    }
}
