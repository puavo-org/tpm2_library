// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{TpmBuild, TpmErrorKind, TpmParse, TpmResult, TpmSized};
use core::{
    convert::TryFrom,
    fmt::Debug,
    mem::{size_of, MaybeUninit},
    ops::Deref,
    slice,
};

/// A fixed-capacity list for TPM structures, implemented over a fixed-size array.
#[derive(Clone, Copy)]
pub struct TpmList<T: Copy, const CAPACITY: usize> {
    items: [MaybeUninit<T>; CAPACITY],
    len: usize,
}

impl<T: Copy, const CAPACITY: usize> TpmList<T, CAPACITY> {
    /// Creates a new, empty `TpmList`.
    ///
    /// # Safety
    ///
    /// This function uses `unsafe` to create an uninitialized array of
    /// `MaybeUninit<T>`. This is a standard and safe pattern as `MaybeUninit`
    /// does not require its contents to be valid.
    #[allow(unsafe_code)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: unsafe { MaybeUninit::uninit().assume_init() },
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
        if self.len >= CAPACITY {
            return Err(TpmErrorKind::CapacityExceeded);
        }
        self.items[self.len].write(item);
        self.len += 1;
        Ok(())
    }
}

#[allow(unsafe_code)]
impl<T: Copy, const CAPACITY: usize> Deref for TpmList<T, CAPACITY> {
    type Target = [T];

    /// # Safety
    ///
    /// This implementation uses `unsafe` to provide a view into the initialized
    /// portion of the list. The caller can rely on this being safe because:
    /// 1. The first `self.len` items are guaranteed to be initialized by the `try_push` method.
    /// 2. `MaybeUninit<T>` is guaranteed to have the same memory layout as `T`.
    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.items.as_ptr().cast::<T>(), self.len) }
    }
}

impl<T: Copy, const CAPACITY: usize> Default for TpmList<T, CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Debug, const CAPACITY: usize> Debug for TpmList<T, CAPACITY> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: Copy + PartialEq, const CAPACITY: usize> PartialEq for TpmList<T, CAPACITY> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<T: Copy + Eq, const CAPACITY: usize> Eq for TpmList<T, CAPACITY> {}

impl<T: TpmSized + Copy, const CAPACITY: usize> TpmSized for TpmList<T, CAPACITY> {
    const SIZE: usize = size_of::<u32>() + (T::SIZE * CAPACITY);
    fn len(&self) -> usize {
        size_of::<u32>() + self.iter().map(TpmSized::len).sum::<usize>()
    }
}

impl<T: TpmBuild + Copy, const CAPACITY: usize> TpmBuild for TpmList<T, CAPACITY> {
    fn build(&self, writer: &mut crate::TpmWriter) -> TpmResult<()> {
        let len_u32 = u32::try_from(self.len).map_err(|_| TpmErrorKind::ValueTooLarge)?;
        TpmBuild::build(&len_u32, writer)?;
        for item in &**self {
            TpmBuild::build(item, writer)?;
        }
        Ok(())
    }
}

impl<T: TpmParse + Copy, const CAPACITY: usize> TpmParse for TpmList<T, CAPACITY> {
    fn parse(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (count_u32, mut buf) = u32::parse(buf)?;
        let count = count_u32 as usize;
        if count > CAPACITY {
            return Err(TpmErrorKind::ValueTooLarge);
        }

        let mut list = Self::new();
        for _ in 0..count {
            let (item, rest) = T::parse(buf)?;
            list.try_push(item).map_err(|_| TpmErrorKind::Unreachable)?;
            buf = rest;
        }

        Ok((list, buf))
    }
}
