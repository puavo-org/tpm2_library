// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

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

        impl $crate::message::TpmHeader for $name {
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

        impl $crate::TpmParse for $name {
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
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
