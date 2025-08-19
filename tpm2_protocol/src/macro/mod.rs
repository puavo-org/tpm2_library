// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

pub mod r#enum;
pub mod integer;
pub mod response;
pub mod r#struct;

#[macro_export]
macro_rules! tpm_bitflags {
    (
        $(#[$outer:meta])*
        $vis:vis struct $name:ident($repr:ty) {
            $(
                $(#[$inner:meta])*
                const $field:ident = $value:expr, $string_name:literal;
            )*
        }
    ) => {
        $(#[$outer])*
        $vis struct $name($repr);

        impl $name {
            $(
                $(#[$inner])*
                pub const $field: Self = Self($value);
            )*

            #[must_use]
            pub const fn bits(&self) -> $repr {
                self.0
            }

            #[must_use]
            pub const fn from_bits_truncate(bits: $repr) -> Self {
                Self(bits)
            }

            #[must_use]
            pub const fn empty() -> Self {
                Self(0)
            }

            #[must_use]
            pub const fn contains(&self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }

            pub fn flag_names(&self) -> impl Iterator<Item = &'static str> + '_ {
                [
                    $(
                        (Self::$field, $string_name),
                    )*
                ]
                .into_iter()
                .filter(move |(flag, _)| self.contains(*flag))
                .map(|(_, name)| name)
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self::Output {
                Self(self.0 | rhs.0)
            }
        }

        impl core::ops::BitOrAssign for $name {
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }

        impl $crate::TpmBuild for $name {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $crate::TpmBuild::build(&self.0, writer)
            }
        }

        impl $crate::TpmParse for $name {
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (val, buf) = <$repr>::parse(buf)?;
                Ok((Self(val), buf))
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = core::mem::size_of::<$repr>();
            fn len(&self) -> usize {
                Self::SIZE
            }
        }
    };
}

#[macro_export]
macro_rules! tpm_bool {
    (
        $(#[$outer:meta])*
        $vis:vis struct $name:ident(bool);
    ) => {
        $(#[$outer])*
        $vis struct $name(pub bool);

        impl From<bool> for $name {
            fn from(val: bool) -> Self {
                Self(val)
            }
        }

        impl From<$name> for bool {
            fn from(val: $name) -> Self {
                val.0
            }
        }

        impl $crate::TpmBuild for $name {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $crate::TpmBuild::build(&u8::from(self.0), writer)
            }
        }

        impl $crate::TpmParse for $name {
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (val, buf) = u8::parse(buf)?;
                match val {
                    0 => Ok((Self(false), buf)),
                    1 => Ok((Self(true), buf)),
                    _ => Err($crate::TpmErrorKind::NotDiscriminant (stringify!($name), TpmNotDiscriminant::Unsigned(u64::from(val)))),
                }
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = core::mem::size_of::<u8>();
            fn len(&self) -> usize {
                Self::SIZE
            }
        }
    };
}

#[macro_export]
macro_rules! tpm_dispatch {
    ( $( ($cmd:ident, $resp:ident, $variant:ident) ),* $(,)? ) => {
        macro_rules! tpm_command_parser {
            ($value:ty, $name:ident) => {
                (
                    <$value as $crate::message::TpmHeader>::COMMAND,
                    <$value as $crate::message::TpmHeader>::NO_SESSIONS,
                    <$value as $crate::message::TpmHeader>::WITH_SESSIONS,
                    <$value as $crate::message::TpmHeader>::HANDLES,
                    |buf| <$value>::parse(buf).map(|(c, r)| (TpmCommandBody::$name(c), r)),
                )
            };
        }

        macro_rules! tpm_response_parser {
            ($rsp_ty:ty, $enum_variant:ident) => {
                (
                    <$rsp_ty as $crate::message::TpmHeader>::COMMAND,
                    <$rsp_ty as $crate::message::TpmHeader>::WITH_SESSIONS,
                    |buf| {
                        <$rsp_ty>::parse(buf)
                            .map(|(r, rest)| (TpmResponseBody::$enum_variant(r), rest))
                    },
                )
            };
        }

        /// A TPM command
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum TpmCommandBody {
            $( $variant($cmd), )*
        }

        /// A TPM response body
        #[allow(clippy::large_enum_variant)]
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum TpmResponseBody {
            $( $variant($resp), )*
        }

        impl TpmResponseBody {
            $(
                /// Attempts to convert the `TpmResponseBody` into a specific response type.
                ///
                /// # Errors
                ///
                /// Returns the original `TpmResponseBody` as an error if the enum variant does not match.
                #[allow(non_snake_case, clippy::result_large_err)]
                pub fn $variant(self) -> Result<$resp, Self> {
                    if let Self::$variant(r) = self {
                        Ok(r)
                    } else {
                        Err(self)
                    }
                }
            )*
        }

        pub type TpmCommandParser = for<'a> fn(&'a [u8]) -> $crate::TpmResult<(TpmCommandBody, &'a [u8])>;
        pub type TpmResponseParser = for<'a> fn(&'a [u8]) -> $crate::TpmResult<(TpmResponseBody, &'a [u8])>;

        pub(crate) static PARSE_COMMAND_MAP: &[($crate::data::TpmCc, bool, bool, usize, TpmCommandParser)] =
            &[$(tpm_command_parser!($cmd, $variant),)*];

        pub(crate) static PARSE_RESPONSE_MAP: &[($crate::data::TpmCc, bool, TpmResponseParser)] =
            &[$(tpm_response_parser!($resp, $variant),)*];

        const _: () = {
            let mut i = 1;
            while i < PARSE_COMMAND_MAP.len() {
                if PARSE_COMMAND_MAP[i - 1].0 as u32 > PARSE_COMMAND_MAP[i].0 as u32 {
                    panic!("PARSE_COMMAND_MAP must be sorted by TpmCc.");
                }
                i += 1;
            }
        };

        const _: () = {
            let mut i = 1;
            while i < PARSE_RESPONSE_MAP.len() {
                if PARSE_RESPONSE_MAP[i - 1].0 as u32 > PARSE_RESPONSE_MAP[i].0 as u32 {
                    panic!("PARSE_RESPONSE_MAP must be sorted by TpmCc.");
                }
                i += 1;
            }
        };
    };
}

#[macro_export]
macro_rules! tpm_handle {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        pub struct $name(pub u32);

        impl From<u32> for $name {
            fn from(val: u32) -> Self {
                Self(val)
            }
        }

        impl From<$name> for u32 {
            fn from(val: $name) -> Self {
                val.0
            }
        }

        impl $crate::TpmBuild for $name {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $crate::TpmBuild::build(&self.0, writer)
            }
        }

        impl $crate::TpmParse for $name {
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (val, buf) = u32::parse(buf)?;
                Ok((Self(val), buf))
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = core::mem::size_of::<u32>();
            fn len(&self) -> usize {
                Self::SIZE
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }

        impl core::fmt::LowerHex for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl core::fmt::UpperHex for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::UpperHex::fmt(&self.0, f)
            }
        }
    };
}

#[macro_export]
macro_rules! tpm2b {
    ($name:ident, $capacity:expr) => {
        pub type $name = $crate::TpmBuffer<$capacity>;
    };
}

#[macro_export]
macro_rules! tpm2b_struct {
    (
        $(#[$meta:meta])*
        $wrapper_ty:ident, $inner_ty:ty) => {
        $(#[$meta])*
        pub struct $wrapper_ty {
            pub inner: $inner_ty,
        }

        impl $crate::TpmSized for $wrapper_ty {
            const SIZE: usize = core::mem::size_of::<u16>() + <$inner_ty>::SIZE;
            fn len(&self) -> usize {
                core::mem::size_of::<u16>() + $crate::TpmSized::len(&self.inner)
            }
        }

        impl $crate::TpmBuild for $wrapper_ty {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                let inner_len = $crate::TpmSized::len(&self.inner);
                u16::try_from(inner_len)
                    .map_err(|_| $crate::TpmErrorKind::ValueTooLarge)?
                    .build(writer)?;
                $crate::TpmBuild::build(&self.inner, writer)
            }
        }

        impl $crate::TpmParse for $wrapper_ty {
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (inner_bytes, rest) = $crate::parse_tpm2b(buf)?;
                let (inner_val, tail) = <$inner_ty>::parse(inner_bytes)?;

                if !tail.is_empty() {
                    return Err($crate::TpmErrorKind::TrailingData);
                }

                Ok((Self { inner: inner_val }, rest))
            }
        }

        impl From<$inner_ty> for $wrapper_ty {
            fn from(inner: $inner_ty) -> Self {
                Self { inner }
            }
        }

        impl core::ops::Deref for $wrapper_ty {
            type Target = $inner_ty;
            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }

        impl core::ops::DerefMut for $wrapper_ty {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.inner
            }
        }
    };
}

#[macro_export]
macro_rules! tpml {
    ($name:ident, $inner_ty:ty, $capacity:expr) => {
        pub type $name = $crate::TpmList<$inner_ty, $capacity>;
    };
}
