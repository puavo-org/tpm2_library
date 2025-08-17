// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

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

        impl $crate::message::TpmHeader for $name {
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
