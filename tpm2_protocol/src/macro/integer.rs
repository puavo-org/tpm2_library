// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#[macro_export]
macro_rules! tpm_integer {
    ($ty:ty, $variant:ident) => {
        impl TpmParse for $ty {
            fn parse(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
                let size = size_of::<$ty>();
                if buf.len() < size {
                    return Err(TpmErrorKind::Boundary);
                }
                let (bytes, buf) = buf.split_at(size);
                let array = bytes.try_into().map_err(|_| TpmErrorKind::Unreachable)?;
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

        impl core::convert::From<$ty> for TpmNotDiscriminant {
            fn from(value: $ty) -> Self {
                Self::$variant(value.into())
            }
        }
    };
}
