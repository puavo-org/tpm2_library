// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{TpmErrorKind, TpmObject, TpmParse, TpmResult};

/// A helper for parsing data from a TPM parameter buffer, which is
/// prefixed with a u32 size.
pub struct TpmParameters<'a> {
    buf: &'a [u8],
}

impl<'a> TpmParameters<'a> {
    /// Creates a new parameter buffer from a slice.
    ///
    /// It reads a `u32` size prefix, slices the buffer accordingly, and returns
    /// the parameter buffer and the remainder of the original buffer.
    ///
    /// # Errors
    ///
    /// Returns `TpmErrorKind::Boundary` if the buffer is too small to contain
    /// the size prefix or the data described by the size prefix.
    /// Returns `TpmErrorKind::ValueTooLarge` if the size prefix exceeds `TPM_MAX_COMMAND_SIZE`.
    pub fn new(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (size, buf) = u32::parse(buf)?;
        let size = size as usize;

        if size > crate::TPM_MAX_COMMAND_SIZE {
            return Err(TpmErrorKind::ValueTooLarge);
        }

        if buf.len() < size {
            return Err(TpmErrorKind::Boundary);
        }
        let (param_data, buf) = buf.split_at(size);
        Ok((Self { buf: param_data }, buf))
    }

    /// Parses a single value from the buffer, advancing the internal cursor.
    ///
    /// # Errors
    ///
    /// Returns any error encountered during the parsing of the inner type `T`.
    pub fn parse<T: TpmObject>(&mut self) -> TpmResult<T> {
        let (value, rest) = T::parse(self.buf)?;
        self.buf = rest;
        Ok(value)
    }

    /// Checks if the entire parameter buffer has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}
