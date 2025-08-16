// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! # TPM 2.0 Protocol
//!
//! A library for building and parsing TCG TPM 2.0 protocol messages.
//!
//! ## Constraints
//!
//! * `alloc` is disallowed.
//! * Dependencies are disallowed.
//! * Developer dependencies are disallowed.
//! * Panics are disallowed.
//!
//! ## Design Goals
//!
//! * The crate must compile with GNU make and rustc without any external
//!   dependencies.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]

#[macro_use]
pub mod r#macro;
pub mod data;
pub mod message;

use crate::data::TpmAlgId;
use core::{convert::TryFrom, fmt, mem::size_of, ops::Deref, result::Result};

tpm_handle!(
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    TpmTransient
);
tpm_handle!(
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    TpmSession
);
tpm_handle!(
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    TpmPersistent
);

/// The maximum size of a TPM command or response buffer.
pub const TPM_MAX_COMMAND_SIZE: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum TpmErrorKind {
    /// Insufficient amount of bytes available
    Boundary,
    /// Trailing data after parsing
    TrailingData,
    /// Not a valid discriminant for the target enum
    InvalidDiscriminant { type_name: &'static str, value: u64 },
    /// Invalid magic number for the data
    InvalidMagic { expected: u32, got: u32 },
    /// Invalid tag for the data
    InvalidTag {
        type_name: &'static str,
        expected: u16,
        got: u16,
    },
    /// Invalid value
    InvalidValue,
    /// A size or count in the buffer is larger than the maximum allowed value
    ValueTooLarge,
    /// An operation would exceed the fixed capacity of a container
    CapacityExceeded,
    /// A command requires an authorization session but none was provided
    AuthMissing,
    /// An unexpected internal error
    InternalError,
}

impl fmt::Display for TpmErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary => write!(f, "Insufficient data in buffer"),
            Self::TrailingData => write!(f, "Buffer has unexpected trailing data after parsing"),
            Self::InvalidDiscriminant { type_name, value } => {
                write!(f, "Invalid discriminant 0x{value:x} for type '{type_name}'")
            }
            Self::InvalidMagic { expected, got } => {
                write!(
                    f,
                    "Invalid magic number: expected 0x{expected:x}, got 0x{got:x}"
                )
            }
            Self::InvalidTag {
                type_name,
                expected,
                got,
            } => {
                write!(
                    f,
                    "Invalid tag for {type_name}: expected 0x{expected:x}, got 0x{got:x}"
                )
            }
            Self::InvalidValue => write!(f, "A value is invalid or out of the expected range"),
            Self::ValueTooLarge => {
                write!(
                    f,
                    "A size or count is larger than the maximum allowed value"
                )
            }
            Self::CapacityExceeded => write!(f, "An operation would exceed a container's capacity"),
            Self::AuthMissing => write!(f, "Command requires authorization but none was provided"),
            Self::InternalError => write!(f, "An unexpected internal error occurred"),
        }
    }
}

impl From<core::num::TryFromIntError> for TpmErrorKind {
    fn from(_: core::num::TryFromIntError) -> Self {
        Self::InternalError
    }
}

pub type TpmResult<T> = Result<T, TpmErrorKind>;

/// Writes into a mutable byte slice.
pub struct TpmWriter<'a> {
    buffer: &'a mut [u8],
    cursor: usize,
}

impl<'a> TpmWriter<'a> {
    /// Creates a new writer for the given buffer.
    #[must_use]
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    /// Returns the number of bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cursor
    }

    /// Returns `true` if no bytes have been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cursor == 0
    }

    /// Appends a slice of bytes to the writer.
    ///
    /// # Errors
    ///
    /// Returns `TpmErrorKind::Boundary` if the writer does not have enough
    /// capacity to hold the new bytes.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> TpmResult<()> {
        let end = self.cursor + bytes.len();
        if end > self.buffer.len() {
            return Err(TpmErrorKind::Boundary);
        }
        self.buffer[self.cursor..end].copy_from_slice(bytes);
        self.cursor = end;
        Ok(())
    }
}

/// Provides two ways to determine the size of an object: a compile-time maximum
/// and a runtime exact size.
pub trait TpmSized {
    /// The estimated size of the object in its serialized form evaluated at
    /// compile-time (always larger than the realized length).
    const SIZE: usize;

    /// Returns the exact serialized size of the object.
    fn len(&self) -> usize;

    /// Returns `true` if the object has a serialized length of zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub trait TpmBuild {
    /// Builds the object into the given writer.
    ///
    /// # Errors
    ///
    /// * `TpmErrorKind::ValueTooLarge` if the object contains a value that cannot be built.
    /// * `TpmErrorKind::Boundary` if the writer runs out of space.
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()>;
}

pub trait TpmParse<'a>: Sized {
    /// Parses an object from the given buffer.
    ///
    /// Returns the parsed type and the remaining portion of the buffer.
    ///
    /// # Errors
    ///
    /// * `TpmErrorKind::Boundary` if the buffer is too small to contain the object.
    /// * `TpmErrorKind::InvalidDiscriminant` if a value in the buffer is invalid for the target type.
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])>;
}

/// Types that are composed of a tag and a value e.g., a union.
pub trait TpmTagged {
    /// The type of the tag/discriminant.
    type Tag: TpmBuild + TpmParse<'static> + Copy;
    /// The type of the value/union.
    type Value;
}

/// Parses a tagged object from a buffer.
pub trait TpmParseTagged<'a>: Sized {
    /// Parses a tagged object from the given buffer using the provided tag.
    ///
    /// # Errors
    ///
    /// This method can return any error of the underlying type's `TpmParse` implementation,
    /// such as a `TpmErrorKind::Boundary` if the buffer is too small or an
    /// `TpmErrorKind::InvalidValue` if the data is malformed.
    fn parse_tagged(tag: <Self as TpmTagged>::Tag, buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])>
    where
        Self: TpmTagged,
        <Self as TpmTagged>::Tag: TpmParse<'a>;
}

impl TpmSized for u8 {
    const SIZE: usize = 1;
    fn len(&self) -> usize {
        1
    }
}

impl TpmBuild for u8 {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        writer.write_bytes(&[*self])
    }
}

impl<'a> TpmParse<'a> for u8 {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (val, buf) = buf.split_first().ok_or(TpmErrorKind::Boundary)?;
        Ok((*val, buf))
    }
}

macro_rules! tpm_integer {
    ($ty:ty) => {
        impl<'a> TpmParse<'a> for $ty {
            fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
                let size = size_of::<$ty>();
                if buf.len() < size {
                    return Err(TpmErrorKind::Boundary);
                }
                let (bytes, buf) = buf.split_at(size);
                let array = bytes.try_into().map_err(|_| TpmErrorKind::InternalError)?;
                let val = <$ty>::from_be_bytes(array);
                Ok((val, buf))
            }
        }

        impl TpmBuild for $ty {
            fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
                writer.write_bytes(&self.to_be_bytes())
            }
        }

        impl TpmSized for $ty {
            const SIZE: usize = size_of::<$ty>();
            fn len(&self) -> usize {
                Self::SIZE
            }
        }
    };
}

tpm_integer!(i32);
tpm_integer!(u16);
tpm_integer!(u32);
tpm_integer!(u64);

/// Builds a TPM2B sized buffer.
///
/// # Errors
///
/// * `TpmErrorKind::ValueTooLarge` if the data slice is too large to fit in a `u16` length.
pub fn build_tpm2b(writer: &mut TpmWriter, data: &[u8]) -> TpmResult<()> {
    u16::try_from(data.len())
        .map_err(|_| TpmErrorKind::ValueTooLarge)?
        .build(writer)?;
    writer.write_bytes(data)
}

/// Parses a TPM2B sized buffer.
///
/// # Errors
///
/// * `TpmErrorKind::Boundary` if the buffer is too small.
/// * `TpmErrorKind::ValueTooLarge` if the size prefix exceeds `TPM_MAX_COMMAND_SIZE`.
pub fn parse_tpm2b(buf: &[u8]) -> TpmResult<(&[u8], &[u8])> {
    let (size, buf) = u16::parse(buf)?;
    let size = size as usize;

    if size > TPM_MAX_COMMAND_SIZE {
        return Err(TpmErrorKind::ValueTooLarge);
    }

    if buf.len() < size {
        return Err(TpmErrorKind::Boundary);
    }
    Ok(buf.split_at(size))
}

/// Returns the size of a hash digest in bytes for a given hash algorithm.
#[must_use]
pub const fn tpm_hash_size(alg_id: &TpmAlgId) -> Option<usize> {
    match alg_id {
        TpmAlgId::Sha1 => Some(20),
        TpmAlgId::Sha256 | TpmAlgId::Sm3_256 => Some(32),
        TpmAlgId::Sha384 => Some(48),
        TpmAlgId::Sha512 => Some(64),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmBuffer<const CAPACITY: usize> {
    bytes: [u8; CAPACITY],
    len: u16,
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
        &self.bytes[..self.len as usize]
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
        size_of::<u16>() + self.len as usize
    }
}

impl<const CAPACITY: usize> TpmBuild for TpmBuffer<CAPACITY> {
    fn build(&self, writer: &mut crate::TpmWriter) -> TpmResult<()> {
        build_tpm2b(writer, self)
    }
}

impl<'a, const CAPACITY: usize> TpmParse<'a> for TpmBuffer<CAPACITY> {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (bytes, remainder) = parse_tpm2b(buf)?;
        if bytes.len() > CAPACITY {
            return Err(TpmErrorKind::ValueTooLarge);
        }
        let mut buffer = Self::new();
        buffer.bytes[..bytes.len()].copy_from_slice(bytes);
        buffer.len = u16::try_from(bytes.len()).map_err(|_| TpmErrorKind::ValueTooLarge)?;
        Ok((buffer, remainder))
    }
}

impl<const CAPACITY: usize> TryFrom<&[u8]> for TpmBuffer<CAPACITY> {
    type Error = TpmErrorKind;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() > CAPACITY {
            return Err(TpmErrorKind::ValueTooLarge);
        }
        let mut buffer = Self::new();
        buffer.bytes[..slice.len()].copy_from_slice(slice);
        buffer.len = u16::try_from(slice.len()).map_err(|_| TpmErrorKind::ValueTooLarge)?;
        Ok(buffer)
    }
}

impl<const CAPACITY: usize> AsRef<[u8]> for TpmBuffer<CAPACITY> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl<const CAPACITY: usize> core::fmt::Debug for TpmBuffer<CAPACITY> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TpmBuffer(")?;
        for byte in &**self {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmList<T: Copy + Default, const CAPACITY: usize> {
    items: [T; CAPACITY],
    len: u32,
}

impl<T: Copy + Default, const CAPACITY: usize> TpmList<T, CAPACITY> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: [T::default(); CAPACITY],
            len: 0,
        }
    }

    /// Returns `true` if the list contains no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends an element to the back of the list.
    ///
    /// # Errors
    ///
    /// Returns a `TpmErrorKind::CapacityExceeded` error if the list is already at
    /// full capacity.
    pub fn try_push(&mut self, item: T) -> Result<(), TpmErrorKind> {
        if self.len as usize >= CAPACITY {
            return Err(TpmErrorKind::CapacityExceeded);
        }
        let index = self.len as usize;
        self.items[index] = item;
        self.len += 1;
        Ok(())
    }
}

impl<T: Copy + Default, const CAPACITY: usize> Deref for TpmList<T, CAPACITY> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.items[..self.len as usize]
    }
}

impl<T: Copy + Default, const CAPACITY: usize> Default for TpmList<T, CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: TpmSized + Copy + Default, const CAPACITY: usize> TpmSized for TpmList<T, CAPACITY> {
    const SIZE: usize = size_of::<u32>() + (T::SIZE * CAPACITY);
    fn len(&self) -> usize {
        size_of::<u32>() + self.iter().map(TpmSized::len).sum::<usize>()
    }
}

impl<T: TpmBuild + Copy + Default, const CAPACITY: usize> TpmBuild for TpmList<T, CAPACITY> {
    fn build(&self, writer: &mut crate::TpmWriter) -> TpmResult<()> {
        self.len.build(writer)?;
        for item in &**self {
            item.build(writer)?;
        }
        Ok(())
    }
}

impl<'a, T: TpmParse<'a> + Copy + Default, const CAPACITY: usize> TpmParse<'a>
    for TpmList<T, CAPACITY>
{
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (count, mut buf) = u32::parse(buf)?;
        let count_usize = count as usize;
        if count_usize > CAPACITY {
            return Err(TpmErrorKind::ValueTooLarge);
        }

        let mut list = Self::new();
        for i in 0..count_usize {
            if buf.is_empty() {
                return Err(TpmErrorKind::Boundary);
            }
            let (item, rest) = T::parse(buf)?;
            list.items[i] = item;
            buf = rest;
        }
        list.len = count;

        Ok((list, buf))
    }
}

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
    pub fn parse<T: TpmParse<'a>>(&mut self) -> TpmResult<T> {
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
