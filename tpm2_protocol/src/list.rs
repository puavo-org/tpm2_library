// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{TpmBuild, TpmErrorKind, TpmParse, TpmResult, TpmSized};
use core::{convert::TryFrom, mem::size_of, ops::Deref};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmList<T: Copy + Default, const CAPACITY: usize> {
    items: [T; CAPACITY],
    len: usize,
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
        if self.len >= CAPACITY {
            return Err(TpmErrorKind::CapacityExceeded);
        }
        self.items[self.len] = item;
        self.len += 1;
        Ok(())
    }
}

impl<T: Copy + Default, const CAPACITY: usize> Deref for TpmList<T, CAPACITY> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.items[..self.len]
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
        let len_u32 = u32::try_from(self.len).map_err(|_| TpmErrorKind::ValueTooLarge)?;
        TpmBuild::build(&len_u32, writer)?;
        for item in &**self {
            TpmBuild::build(item, writer)?;
        }
        Ok(())
    }
}

impl<T: TpmParse + Copy + Default, const CAPACITY: usize> TpmParse for TpmList<T, CAPACITY> {
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
