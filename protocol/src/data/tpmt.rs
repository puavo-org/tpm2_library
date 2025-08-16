// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

use super::{
    tpmu::{
        TpmuHa, TpmuPublicId, TpmuPublicParms, TpmuSensitiveComposite, TpmuSignature,
        TpmuSymKeyBits, TpmuSymMode,
    },
    Tpm2bAuth, Tpm2bDigest, TpmAlgId, TpmRh, TpmSt, TpmaObject,
};
use crate::{
    tpm_struct, tpm_tagged_struct, TpmBuild, TpmErrorKind, TpmParse, TpmParseTagged, TpmResult,
    TpmSized, TpmTagged, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TpmtPublic {
    pub object_type: TpmAlgId,
    pub name_alg: TpmAlgId,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest,
    pub parameters: TpmuPublicParms,
    pub unique: TpmuPublicId,
}

impl TpmTagged for TpmtPublic {
    type Tag = TpmAlgId;
    type Value = TpmuPublicParms;
}

impl TpmSized for TpmtPublic {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        self.object_type.len()
            + self.name_alg.len()
            + self.object_attributes.len()
            + self.auth_policy.len()
            + self.parameters.len()
            + self.unique.len()
    }
}

impl TpmBuild for TpmtPublic {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.object_type.build(writer)?;
        self.name_alg.build(writer)?;
        self.object_attributes.build(writer)?;
        self.auth_policy.build(writer)?;
        self.parameters.build(writer)?;
        self.unique.build(writer)
    }
}

impl<'a> TpmParse<'a> for TpmtPublic {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (object_type, mut buf) = TpmAlgId::parse(buf)?;
        let (name_alg, rest) = TpmAlgId::parse(buf)?;
        buf = rest;
        let (object_attributes, rest) = TpmaObject::parse(buf)?;
        buf = rest;
        let (auth_policy, rest) = Tpm2bDigest::parse(buf)?;
        buf = rest;
        let (parameters, rest) = TpmuPublicParms::parse_tagged(object_type, buf)?;
        buf = rest;
        let (unique, rest) = TpmuPublicId::parse_tagged(object_type, buf)?;
        buf = rest;

        let public_area = Self {
            object_type,
            name_alg,
            object_attributes,
            auth_policy,
            parameters,
            unique,
        };

        Ok((public_area, buf))
    }
}

impl Default for TpmtPublic {
    fn default() -> Self {
        Self {
            object_type: TpmAlgId::Null,
            name_alg: TpmAlgId::Sha256,
            object_attributes: TpmaObject::empty(),
            auth_policy: Tpm2bDigest::default(),
            parameters: TpmuPublicParms::Null,
            unique: TpmuPublicId::Null,
        }
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtScheme {
        pub scheme: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtKdfScheme {
        pub scheme: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtRsaDecrypt {
        pub scheme: TpmtScheme,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct TpmtSensitive {
    pub sensitive_type: TpmAlgId,
    pub auth_value: Tpm2bAuth,
    pub seed_value: Tpm2bDigest,
    pub sensitive: TpmuSensitiveComposite,
}

impl TpmtSensitive {
    /// Constructs a `TpmtSensitive` from a given key algorithm and raw private key bytes.
    ///
    /// # Errors
    ///
    /// Returns a `TpmErrorKind::InvalidValue` if the key algorithm is not supported for this operation.
    pub fn from_private_bytes(
        key_alg: TpmAlgId,
        private_bytes: &[u8],
    ) -> Result<Self, TpmErrorKind> {
        let sensitive = match key_alg {
            TpmAlgId::Rsa => TpmuSensitiveComposite::Rsa(
                crate::data::Tpm2bPrivateKeyRsa::try_from(private_bytes)?,
            ),
            TpmAlgId::Ecc => TpmuSensitiveComposite::Ecc(crate::data::Tpm2bEccParameter::try_from(
                private_bytes,
            )?),
            TpmAlgId::KeyedHash => TpmuSensitiveComposite::Bits(
                crate::data::Tpm2bSensitiveData::try_from(private_bytes)?,
            ),
            TpmAlgId::SymCipher => {
                TpmuSensitiveComposite::Sym(crate::data::Tpm2bSymKey::try_from(private_bytes)?)
            }
            _ => return Err(TpmErrorKind::InvalidValue),
        };

        Ok(Self {
            sensitive_type: key_alg,
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::default(),
            sensitive,
        })
    }
}

impl TpmTagged for TpmtSensitive {
    type Tag = TpmAlgId;
    type Value = TpmuSensitiveComposite;
}

impl TpmSized for TpmtSensitive {
    const SIZE: usize =
        TpmAlgId::SIZE + Tpm2bAuth::SIZE + Tpm2bDigest::SIZE + TpmuSensitiveComposite::SIZE;
    fn len(&self) -> usize {
        self.sensitive_type.len()
            + self.auth_value.len()
            + self.seed_value.len()
            + self.sensitive.len()
    }
}

impl TpmBuild for TpmtSensitive {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.sensitive_type.build(writer)?;
        self.auth_value.build(writer)?;
        self.seed_value.build(writer)?;
        self.sensitive.build(writer)
    }
}

impl<'a> TpmParse<'a> for TpmtSensitive {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (sensitive_type, buf) = TpmAlgId::parse(buf)?;
        let (auth_value, buf) = Tpm2bAuth::parse(buf)?;
        let (seed_value, buf) = Tpm2bDigest::parse(buf)?;
        let (sensitive, buf) = TpmuSensitiveComposite::parse_tagged(sensitive_type, buf)?;

        Ok((
            Self {
                sensitive_type,
                auth_value,
                seed_value,
                sensitive,
            },
            buf,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct TpmtSymDef {
    pub algorithm: TpmAlgId,
    pub key_bits: TpmuSymKeyBits,
    pub mode: TpmuSymMode,
}

impl TpmTagged for TpmtSymDef {
    type Tag = TpmAlgId;
    type Value = TpmuSymKeyBits;
}

impl TpmSized for TpmtSymDef {
    const SIZE: usize = TpmAlgId::SIZE + TpmuSymKeyBits::SIZE + TpmAlgId::SIZE;
    fn len(&self) -> usize {
        if self.algorithm == TpmAlgId::Null {
            self.algorithm.len()
        } else {
            self.algorithm.len() + self.key_bits.len() + self.mode.len()
        }
    }
}

impl TpmBuild for TpmtSymDef {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.algorithm.build(writer)?;
        if self.algorithm != TpmAlgId::Null {
            self.key_bits.build(writer)?;
            self.mode.build(writer)?;
        }
        Ok(())
    }
}

impl<'a> TpmParse<'a> for TpmtSymDef {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (algorithm, buf) = TpmAlgId::parse(buf)?;
        if algorithm == TpmAlgId::Null {
            Ok((
                Self {
                    algorithm,
                    key_bits: TpmuSymKeyBits::Null,
                    mode: TpmuSymMode::Null,
                },
                buf,
            ))
        } else {
            let (key_bits, buf) = TpmuSymKeyBits::parse_tagged(algorithm, buf)?;
            let (mode, buf) = TpmuSymMode::parse_tagged(algorithm, buf)?;
            Ok((
                Self {
                    algorithm,
                    key_bits,
                    mode,
                },
                buf,
            ))
        }
    }
}

pub type TpmtSymDefObject = TpmtSymDef;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmtTkCreation {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtTkVerified {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtTkHashcheck {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_tagged_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct TpmtHa {
        pub hash_alg: TpmAlgId,
        pub digest: TpmuHa,
    }
}

impl Default for TpmtHa {
    fn default() -> Self {
        Self {
            hash_alg: TpmAlgId::Sha256,
            digest: TpmuHa::default(),
        }
    }
}

tpm_tagged_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct TpmtSignature {
        pub sig_alg: TpmAlgId,
        pub signature: TpmuSignature,
    }
}
