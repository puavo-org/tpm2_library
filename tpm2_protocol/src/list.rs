// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

use crate::{TpmBuild, TpmErrorKind, TpmObject, TpmResult, TpmSized};
use core::{mem::size_of, ops::Deref};

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

impl<'a, T: TpmObject<'a> + Copy + Default, const CAPACITY: usize> crate::TpmParse<'a>
    for TpmList<T, CAPACITY>
{
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (count, mut buf) = u32::parse(buf)?;
        let count_usize = count as usize;
        if count_usize > CAPACITY {
            return Err(TpmErrorKind::ValueTooLarge);
        }

        let mut list = Self::new();
        for _ in 0..count_usize {
            let (item, rest) = T::parse(buf)?;
            list.try_push(item)
                .map_err(|_| TpmErrorKind::InternalError)?;
            buf = rest;
        }

        Ok((list, buf))
    }
}
