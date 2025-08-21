// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#[macro_export]
macro_rules! tpm_struct {
    (
        $(#[$meta:meta])*
        kind: Command,
        name: $name:ident,
        cc: $cc:expr,
        no_sessions: $no_sessions:expr,
        with_sessions: $with_sessions:expr,
        handles: {
            $(pub $handle_field:ident: $handle_type:ty),*
            $(,)?
        },
        parameters: {
            $(pub $param_field:ident: $param_type:ty),*
            $(,)?
        }
    ) => {
        $(#[$meta])*
        pub struct $name {
            $(pub $handle_field: $handle_type,)*
            $(pub $param_field: $param_type,)*
        }

        impl $name {
            #[allow(unused_variables)]
            pub(crate) fn build_handles(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $($crate::TpmBuild::build(&self.$handle_field, writer)?;)*
                Ok(())
            }

            #[allow(unused_variables)]
            pub(crate) fn build_parameters(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $($crate::TpmBuild::build(&self.$param_field, writer)?;)*
                Ok(())
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = 0 $(+ <$handle_type>::SIZE)* $(+ <$param_type>::SIZE)*;
            fn len(&self) -> usize {
                0 $(+ $crate::TpmSized::len(&self.$handle_field))* $(+ $crate::TpmSized::len(&self.$param_field))*
            }
        }

        impl $crate::TpmBuild for $name {
            #[allow(unused_variables)]
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                self.build_handles(writer)?;
                self.build_parameters(writer)
            }
        }

        impl $crate::message::TpmHeaderCommand for $name {
            #[allow(unused_variables)]
            fn build_handles(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $($crate::TpmBuild::build(&self.$handle_field, writer)?;)*
                Ok(())
            }

            #[allow(unused_variables)]
            fn build_parameters(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $($crate::TpmBuild::build(&self.$param_field, writer)?;)*
                Ok(())
            }
        }

        impl $crate::TpmParse for $name {
            #[allow(unused_mut)]
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let mut cursor = buf;
                $(
                    let ($handle_field, tail) = <$handle_type>::parse(cursor)?;
                    cursor = tail;
                )*
                $(
                    let ($param_field, tail) = <$param_type>::parse(cursor)?;
                    cursor = tail;
                )*
                Ok((
                    Self {
                        $($handle_field,)*
                        $($param_field,)*
                    },
                    cursor,
                ))
            }
        }

        impl $crate::message::TpmHeader for $name {
            const COMMAND: $crate::data::TpmCc = $cc;
            const NO_SESSIONS: bool = $no_sessions;
            const WITH_SESSIONS: bool = $with_sessions;
            const HANDLES: usize = 0 $(+ {let _ = stringify!($handle_field); 1})*;
        }
    };

    (
        $(#[$meta:meta])*
        kind: Response,
        name: $name:ident,
        cc: $cc:expr,
        no_sessions: $no_sessions:expr,
        with_sessions: $with_sessions:expr,
        handles: {
            $(pub $handle_field:ident: $handle_type:ty),*
            $(,)?
        },
        parameters: {
            $(pub $param_field:ident: $param_type:ty),*
            $(,)?
        }
    ) => {
        $(#[$meta])*
        pub struct $name {
            $(pub $handle_field: $handle_type,)*
            $(pub $param_field: $param_type,)*
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = 0 $(+ <$handle_type>::SIZE)* $(+ <$param_type>::SIZE)*;
            fn len(&self) -> usize {
                let params_len: usize = 0 $(+ $crate::TpmSized::len(&self.$param_field))*;
                let handles_len: usize = 0 $(+ $crate::TpmSized::len(&self.$handle_field))*;
                let parameter_area_size_field_len: usize = if $with_sessions {
                    core::mem::size_of::<u32>()
                } else {
                    0
                };
                handles_len + parameter_area_size_field_len + params_len
            }
        }

        impl $crate::TpmBuild for $name {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                let params_len: usize = 0 $(+ $crate::TpmSized::len(&self.$param_field))*;
                $($crate::TpmBuild::build(&self.$handle_field, writer)?;)*
                if $with_sessions {
                    let params_len_u32 = u32::try_from(params_len)
                        .map_err(|_| $crate::TpmErrorKind::ValueTooLarge)?;
                    $crate::TpmBuild::build(&params_len_u32, writer)?;
                }
                $($crate::TpmBuild::build(&self.$param_field, writer)?;)*
                Ok(())
            }
        }

        impl $crate::TpmParse for $name {
            #[allow(unused_mut)]
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let mut cursor = buf;
                $(
                    let ($handle_field, tail) = <$handle_type>::parse(cursor)?;
                    cursor = tail;
                )*

                if $with_sessions {
                    let (size, buf_after_size) = u32::parse(cursor)?;
                    let size = size as usize;
                    if buf_after_size.len() < size {
                        return Err($crate::TpmErrorKind::Boundary);
                    }
                    let (mut params_cursor, final_tail) = buf_after_size.split_at(size);

                    $(
                        let ($param_field, tail) = <$param_type>::parse(params_cursor)?;
                        params_cursor = tail;
                    )*

                    if !params_cursor.is_empty() {
                        return Err($crate::TpmErrorKind::TrailingData);
                    }

                    Ok((
                        Self {
                            $($handle_field,)*
                            $($param_field,)*
                        },
                        final_tail,
                    ))
                } else {
                    let mut params_cursor = cursor;
                    $(
                        let ($param_field, tail) = <$param_type>::parse(params_cursor)?;
                        params_cursor = tail;
                    )*

                    Ok((
                        Self {
                            $($handle_field,)*
                            $($param_field,)*
                        },
                        params_cursor,
                    ))
                }
            }
        }

        impl $crate::message::TpmHeader for $name {
            const COMMAND: $crate::data::TpmCc = $cc;
            const NO_SESSIONS: bool = $no_sessions;
            const WITH_SESSIONS: bool = $with_sessions;
            const HANDLES: usize = 0 $(+ {let _ = stringify!($handle_field); 1})*;
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
                0 $(+ $crate::TpmSized::len(&self.$field_name))*
            }
        }

        impl $crate::TpmBuild for $name {
            #[allow(unused_variables)]
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $( $crate::TpmBuild::build(&self.$field_name, writer)?; )*
                Ok(())
            }
        }

        impl $crate::TpmParse for $name {
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
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
                $crate::TpmSized::len(&self.$tag_field) + $crate::TpmSized::len(&self.$value_field)
            }
        }

        impl $crate::TpmBuild for $name {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $crate::TpmBuild::build(&self.$tag_field, writer)?;
                $crate::TpmBuild::build(&self.$value_field, writer)
            }
        }

        impl $crate::TpmParse for $name {
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
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
