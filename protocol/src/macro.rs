// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

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
                self.0.build(writer)
            }
        }

        impl<'a> $crate::TpmParse<'a> for $name {
            fn parse(buf: &'a [u8]) -> $crate::TpmResult<(Self, &'a [u8])> {
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
                u8::from(self.0).build(writer)
            }
        }

        impl<'a> $crate::TpmParse<'a> for $name {
            fn parse(buf: &'a [u8]) -> $crate::TpmResult<(Self, &'a [u8])> {
                let (val, buf) = u8::parse(buf)?;
                match val {
                    0 => Ok((Self(false), buf)),
                    1 => Ok((Self(true), buf)),
                    _ => Err($crate::TpmErrorKind::InvalidDiscriminant {
                        type_name: stringify!($name),
                        value: u64::from(val),
                    }),
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
macro_rules! tpm_enum {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident($repr:ty) {
            $(
                $(#[$variant_meta:meta])*
                ($variant:ident, $value:expr, $display:literal)
            ),* $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[repr($repr)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant = $value
            ),*
        }

        impl TryFrom<$repr> for $name {
            type Error = ();

            #[allow(clippy::cognitive_complexity)]
            fn try_from(value: $repr) -> Result<Self, ()> {
                $(
                    if value == $value {
                        return Ok(Self::$variant);
                    }
                )*
                Err(())
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let s = match self {
                    $(Self::$variant => $display),*
                };
                write!(f, "{}", s)
            }
        }

        impl core::str::FromStr for $name {
            type Err = ();

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($display => Ok(Self::$variant),)*
                    _ => Err(()),
                }
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = core::mem::size_of::<$repr>();

            fn len(&self) -> usize {
                Self::SIZE
            }
        }

        impl $crate::TpmBuild for $name {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                (*self as $repr).build(writer)
            }
        }

        impl<'a> $crate::TpmParse<'a> for $name {
            fn parse(buf: &'a [u8]) -> $crate::TpmResult<(Self, &'a [u8])> {
                let (val, buf) = <$repr>::parse(buf)?;
                let enum_val = Self::try_from(val).map_err(|()| $crate::TpmErrorKind::InvalidDiscriminant {
                    type_name: stringify!($name),
                    value: u64::from(val)
                })?;
                Ok((enum_val, buf))
            }
        }
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
                self.0.build(writer)
            }
        }

        impl<'a> $crate::TpmParse<'a> for $name {
            fn parse(buf: &'a [u8]) -> $crate::TpmResult<(Self, &'a [u8])> {
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
macro_rules! tpm_response {
    (
        $(#[$meta:meta])*
        $name:ident,
        $cc:expr,
        $no_sessions:expr,
        $with_sessions:expr,
        $(pub $handle_field:ident: $handle_type:ty,)*
        {
            $(pub $param_field:ident: $param_type:ty),*
            $(,)?
        }
    ) => {
        $(#[$meta])*
        pub struct $name {
            $(pub $handle_field: $handle_type,)*
            $(pub $param_field: $param_type,)*
        }

        impl $crate::message::TpmHeader<'_> for $name {
            const COMMAND: $crate::data::TpmCc = $cc;
            const NO_SESSIONS: bool = $no_sessions;
            const WITH_SESSIONS: bool = $with_sessions;
            const HANDLES: usize = 0 $(+ {let _ = stringify!($handle_field); 1})*;
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = 0 $(+ <$handle_type>::SIZE)* $(+ <$param_type>::SIZE)*;
            fn len(&self) -> usize {
                let params_len: usize = 0 $(+ self.$param_field.len())*;
                let handles_len: usize = 0 $(+ self.$handle_field.len())*;
                let parameter_area_size_field_len: usize = core::mem::size_of::<u32>();
                handles_len + parameter_area_size_field_len + params_len
            }
        }

        impl $crate::TpmBuild for $name {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                let params_len: usize = 0 $(+ self.$param_field.len())*;
                let params_len_u32 = u32::try_from(params_len)
                    .map_err(|_| $crate::TpmErrorKind::ValueTooLarge)?;

                $(self.$handle_field.build(writer)?;)*
                params_len_u32.build(writer)?;
                $(self.$param_field.build(writer)?;)*

                Ok(())
            }
        }

        impl<'a> $crate::TpmParse<'a> for $name {
            fn parse(buf: &'a [u8]) -> $crate::TpmResult<(Self, &'a [u8])> {
                #[allow(unused_mut)]
                let mut cursor = buf;
                $(
                    let ($handle_field, tail) = <$handle_type>::parse(cursor)?;
                    cursor = tail;
                )*

                #[allow(unused_mut)]
                let (mut params, tail) = $crate::TpmParameters::new(cursor)?;
                $(
                    let $param_field = params.parse::<$param_type>()?;
                )*
                if !params.is_empty() {
                    return Err($crate::TpmErrorKind::TrailingData);
                }

                Ok((
                    Self {
                        $( $handle_field, )*
                        $( $param_field, )*
                    },
                    tail,
                ))
            }
        }
    };
}

#[macro_export]
macro_rules! tpm_struct {
    (
        $(#[$meta:meta])*
        $name:ident,
        $cc:expr,
        $no_sessions:expr,
        $with_sessions:expr,
        $handles:expr,
        {
            $(pub $field_name:ident: $field_type:ty),*
            $(,)?
        }
    ) => {
        $crate::tpm_struct! {
            $(#[$meta])*
            pub struct $name {
                $(pub $field_name: $field_type,)*
            }
        }

        impl $crate::message::TpmHeader<'_> for $name {
            const COMMAND: $crate::data::TpmCc = $cc;
            const NO_SESSIONS: bool = $no_sessions;
            const WITH_SESSIONS: bool = $with_sessions;
            const HANDLES: usize = $handles;
        }
    };

    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(pub $field_name:ident: $field_type:ty),*
            $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $(pub $field_name: $field_type,)*
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = 0 $(+ <$field_type>::SIZE)*;
            fn len(&self) -> usize {
                0 $(+ self.$field_name.len())*
            }
        }

        impl $crate::TpmBuild for $name {
            #[allow(unused_variables)]
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $(self.$field_name.build(writer)?;)*
                Ok(())
            }
        }

        impl<'a> $crate::TpmParse<'a> for $name {
            fn parse(buf: &'a [u8]) -> $crate::TpmResult<(Self, &'a [u8])> {
                $(let ($field_name, buf) = <$field_type>::parse(buf)?;)*
                Ok((
                    Self {
                        $($field_name,)*
                    },
                    buf,
                ))
            }
        }
    };
}

#[macro_export]
macro_rules! tpm_tagged_struct {
    (
        $(#[$outer:meta])*
        $vis:vis struct $name:ident {
            pub $tag_field:ident: $tag_ty:ty,
            pub $value_field:ident: $value_ty:ty,
        }
    ) => {
        $(#[$outer])*
        $vis struct $name {
            pub $tag_field: $tag_ty,
            pub $value_field: $value_ty,
        }

        impl $crate::TpmTagged for $name {
            type Tag = $tag_ty;
            type Value = $value_ty;
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = <$tag_ty>::SIZE + <$value_ty>::SIZE;
            fn len(&self) -> usize {
                self.$tag_field.len() + self.$value_field.len()
            }
        }

        impl $crate::TpmBuild for $name {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                self.$tag_field.build(writer)?;
                self.$value_field.build(writer)
            }
        }

        impl<'a> $crate::TpmParse<'a> for $name {
            fn parse(buf: &'a [u8]) -> $crate::TpmResult<(Self, &'a [u8])> {
                let ($tag_field, buf) = <$tag_ty>::parse(buf)?;
                let ($value_field, buf) =
                    <$value_ty as $crate::TpmParseTagged>::parse_tagged($tag_field, buf)?;
                Ok((
                    Self {
                        $tag_field,
                        $value_field,
                    },
                    buf,
                ))
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
                core::mem::size_of::<u16>() + self.inner.len()
            }
        }

        impl $crate::TpmBuild for $wrapper_ty {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                let inner_len = self.inner.len();
                u16::try_from(inner_len)
                    .map_err(|_| $crate::TpmErrorKind::ValueTooLarge)?
                    .build(writer)?;
                self.inner.build(writer)
            }
        }

        impl<'a> $crate::TpmParse<'a> for $wrapper_ty {
            fn parse(buf: &'a [u8]) -> $crate::TpmResult<(Self, &'a [u8])> {
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
