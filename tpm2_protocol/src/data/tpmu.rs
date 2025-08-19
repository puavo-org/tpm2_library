// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    data::{
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bSymKey,
        TpmAlgId, TpmCap, TpmlAlgProperty, TpmlHandle, TpmlPcrSelection, TpmsCertifyInfo,
        TpmsCommandAuditInfo, TpmsCreationInfo, TpmsEccParms, TpmsEccPoint, TpmsKeyedhashParms,
        TpmsNvCertifyInfo, TpmsNvDigestCertifyInfo, TpmsQuoteInfo, TpmsRsaParms, TpmsSchemeHash,
        TpmsSchemeXor, TpmsSessionAuditInfo, TpmsSignatureEcc, TpmsSignatureRsa,
        TpmsSymcipherParms, TpmsTimeAttestInfo, TpmtHa,
    },
    tpm_hash_size, TpmBuild, TpmErrorKind, TpmParse, TpmParseTagged, TpmResult, TpmSized,
    TpmTagged, TpmWriter, TPM_MAX_COMMAND_SIZE,
};
use core::ops::Deref;

/// A helper to convert a slice into a fixed-size array, returning an internal error on failure.
fn slice_to_fixed_array<const N: usize>(slice: &[u8]) -> TpmResult<[u8; N]> {
    slice.try_into().map_err(|_| TpmErrorKind::InternalError)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuCapabilities {
    Algs(TpmlAlgProperty),
    Handles(TpmlHandle),
    Pcrs(TpmlPcrSelection),
}

impl TpmTagged for TpmuCapabilities {
    type Tag = TpmCap;
    type Value = ();
}

impl TpmSized for TpmuCapabilities {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Algs(algs) => algs.len(),
            Self::Handles(handles) => handles.len(),
            Self::Pcrs(pcrs) => pcrs.len(),
        }
    }
}

impl TpmBuild for TpmuCapabilities {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Algs(algs) => algs.build(writer),
            Self::Handles(handles) => handles.build(writer),
            Self::Pcrs(pcrs) => pcrs.build(writer),
        }
    }
}

impl TpmParseTagged for TpmuCapabilities {
    fn parse_tagged(tag: TpmCap, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmCap::Algs => {
                let (algs, buf) = TpmlAlgProperty::parse(buf)?;
                Ok((Self::Algs(algs), buf))
            }
            TpmCap::Handles => {
                let (handles, buf) = TpmlHandle::parse(buf)?;
                Ok((Self::Handles(handles), buf))
            }
            TpmCap::Pcrs => {
                let (pcrs, buf) = TpmlPcrSelection::parse(buf)?;
                Ok((Self::Pcrs(pcrs), buf))
            }
            TpmCap::Commands => Err(TpmErrorKind::InvalidValue),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuHa {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
    Sm3_256([u8; 32]),
}

impl TpmTagged for TpmuHa {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmBuild for TpmuHa {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        writer.write_bytes(self)
    }
}

impl TpmParseTagged for TpmuHa {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let digest_size = tpm_hash_size(&tag).ok_or(TpmErrorKind::InvalidValue)?;
        if buf.len() < digest_size {
            return Err(TpmErrorKind::Boundary);
        }

        let (digest_bytes, buf) = buf.split_at(digest_size);

        let digest = match tag {
            TpmAlgId::Sha1 => Self::Sha1(slice_to_fixed_array(digest_bytes)?),
            TpmAlgId::Sha256 => Self::Sha256(slice_to_fixed_array(digest_bytes)?),
            TpmAlgId::Sha384 => Self::Sha384(slice_to_fixed_array(digest_bytes)?),
            TpmAlgId::Sha512 => Self::Sha512(slice_to_fixed_array(digest_bytes)?),
            TpmAlgId::Sm3_256 => Self::Sm3_256(slice_to_fixed_array(digest_bytes)?),
            _ => return Err(TpmErrorKind::InvalidValue),
        };

        Ok((digest, buf))
    }
}

impl Default for TpmuHa {
    fn default() -> Self {
        Self::Sha256([0; 32])
    }
}

impl TpmSized for TpmuHa {
    const SIZE: usize = 64;
    fn len(&self) -> usize {
        match self {
            Self::Sha1(d) => d.len(),
            Self::Sha256(d) | Self::Sm3_256(d) => d.len(),
            Self::Sha384(d) => d.len(),
            Self::Sha512(d) => d.len(),
        }
    }
}

impl Deref for TpmuHa {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Sha1(d) => d,
            Self::Sha256(d) | Self::Sm3_256(d) => d,
            Self::Sha384(d) => d,
            Self::Sha512(d) => d,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuPublicId {
    KeyedHash(Tpm2bDigest),
    SymCipher(Tpm2bSymKey),
    Rsa(Tpm2bPublicKeyRsa),
    Ecc(TpmsEccPoint),
    Null,
}

impl TpmTagged for TpmuPublicId {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmuPublicId {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::KeyedHash(data) => data.len(),
            Self::SymCipher(data) => data.len(),
            Self::Rsa(data) => data.len(),
            Self::Ecc(point) => point.len(),
            Self::Null => 0,
        }
    }
}

impl TpmBuild for TpmuPublicId {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::KeyedHash(data) => data.build(writer),
            Self::SymCipher(data) => data.build(writer),
            Self::Rsa(data) => data.build(writer),
            Self::Ecc(point) => point.build(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmParseTagged for TpmuPublicId {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::KeyedHash => {
                let (val, rest) = Tpm2bDigest::parse(buf)?;
                Ok((Self::KeyedHash(val), rest))
            }
            TpmAlgId::SymCipher => {
                let (val, rest) = Tpm2bSymKey::parse(buf)?;
                Ok((Self::SymCipher(val), rest))
            }
            TpmAlgId::Rsa => {
                let (val, rest) = Tpm2bPublicKeyRsa::parse(buf)?;
                Ok((Self::Rsa(val), rest))
            }
            TpmAlgId::Ecc => {
                let (point, rest) = TpmsEccPoint::parse(buf)?;
                Ok((Self::Ecc(point), rest))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

impl Default for TpmuPublicId {
    fn default() -> Self {
        Self::Null
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuPublicParms {
    KeyedHash(TpmsKeyedhashParms),
    SymCipher(TpmsSymcipherParms),
    Rsa(TpmsRsaParms),
    Ecc(TpmsEccParms),
    Null,
}

impl TpmTagged for TpmuPublicParms {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmuPublicParms {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::KeyedHash(d) => d.len(),
            Self::SymCipher(d) => d.len(),
            Self::Rsa(d) => d.len(),
            Self::Ecc(d) => d.len(),
            Self::Null => 0,
        }
    }
}

impl TpmBuild for TpmuPublicParms {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::KeyedHash(d) => d.build(writer),
            Self::SymCipher(d) => d.build(writer),
            Self::Rsa(d) => d.build(writer),
            Self::Ecc(d) => d.build(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmParseTagged for TpmuPublicParms {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::KeyedHash => {
                let (details, buf) = TpmsKeyedhashParms::parse(buf)?;
                Ok((Self::KeyedHash(details), buf))
            }
            TpmAlgId::SymCipher => {
                let (details, buf) = TpmsSymcipherParms::parse(buf)?;
                Ok((Self::SymCipher(details), buf))
            }
            TpmAlgId::Rsa => {
                let (details, buf) = TpmsRsaParms::parse(buf)?;
                Ok((Self::Rsa(details), buf))
            }
            TpmAlgId::Ecc => {
                let (details, buf) = TpmsEccParms::parse(buf)?;
                Ok((Self::Ecc(details), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuSensitiveComposite {
    Rsa(crate::data::Tpm2bPrivateKeyRsa),
    Ecc(Tpm2bEccParameter),
    Bits(Tpm2bSensitiveData),
    Sym(Tpm2bSymKey),
}

impl TpmTagged for TpmuSensitiveComposite {
    type Tag = TpmAlgId;
    type Value = ();
}

impl Default for TpmuSensitiveComposite {
    fn default() -> Self {
        Self::Rsa(crate::data::Tpm2bPrivateKeyRsa::default())
    }
}

impl TpmSized for TpmuSensitiveComposite {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Rsa(val) => val.len(),
            Self::Ecc(val) => val.len(),
            Self::Bits(val) => val.len(),
            Self::Sym(val) => val.len(),
        }
    }
}

impl TpmBuild for TpmuSensitiveComposite {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Rsa(val) => val.build(writer),
            Self::Ecc(val) => val.build(writer),
            Self::Bits(val) => val.build(writer),
            Self::Sym(val) => val.build(writer),
        }
    }
}

impl TpmParseTagged for TpmuSensitiveComposite {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Rsa => {
                let (val, buf) = crate::data::Tpm2bPrivateKeyRsa::parse(buf)?;
                Ok((Self::Rsa(val), buf))
            }
            TpmAlgId::Ecc => {
                let (val, buf) = Tpm2bEccParameter::parse(buf)?;
                Ok((Self::Ecc(val), buf))
            }
            TpmAlgId::KeyedHash => {
                let (val, buf) = Tpm2bSensitiveData::parse(buf)?;
                Ok((Self::Bits(val), buf))
            }
            TpmAlgId::SymCipher => {
                let (val, buf) = Tpm2bSymKey::parse(buf)?;
                Ok((Self::Sym(val), buf))
            }
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuSymKeyBits {
    Aes(u16),
    Sm4(u16),
    Camellia(u16),
    Xor(TpmAlgId),
    Null,
}

impl TpmTagged for TpmuSymKeyBits {
    type Tag = TpmAlgId;
    type Value = ();
}

impl Default for TpmuSymKeyBits {
    fn default() -> Self {
        Self::Null
    }
}

impl TpmSized for TpmuSymKeyBits {
    const SIZE: usize = core::mem::size_of::<u16>();
    fn len(&self) -> usize {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) => val.len(),
            Self::Xor(val) => val.len(),
            Self::Null => 0,
        }
    }
}

impl TpmParseTagged for TpmuSymKeyBits {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Aes => {
                let (val, buf) = u16::parse(buf)?;
                Ok((Self::Aes(val), buf))
            }
            TpmAlgId::Sm4 => {
                let (val, buf) = u16::parse(buf)?;
                Ok((Self::Sm4(val), buf))
            }
            TpmAlgId::Camellia => {
                let (val, buf) = u16::parse(buf)?;
                Ok((Self::Camellia(val), buf))
            }
            TpmAlgId::Xor => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                Ok((Self::Xor(val), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

impl TpmBuild for TpmuSymKeyBits {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) => val.build(writer),
            Self::Xor(val) => val.build(writer),
            Self::Null => Ok(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuSymMode {
    Aes(TpmAlgId),
    Sm4(TpmAlgId),
    Camellia(TpmAlgId),
    Xor(TpmAlgId),
    Null,
}

impl TpmTagged for TpmuSymMode {
    type Tag = TpmAlgId;
    type Value = ();
}

impl Default for TpmuSymMode {
    fn default() -> Self {
        Self::Null
    }
}

impl TpmSized for TpmuSymMode {
    const SIZE: usize = core::mem::size_of::<u16>();
    fn len(&self) -> usize {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) | Self::Xor(val) => val.len(),
            Self::Null => 0,
        }
    }
}

impl TpmParseTagged for TpmuSymMode {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Aes => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                Ok((Self::Aes(val), buf))
            }
            TpmAlgId::Sm4 => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                Ok((Self::Sm4(val), buf))
            }
            TpmAlgId::Camellia => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                Ok((Self::Camellia(val), buf))
            }
            TpmAlgId::Xor => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                Ok((Self::Xor(val), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

impl TpmBuild for TpmuSymMode {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) | Self::Xor(val) => {
                val.build(writer)
            }
            Self::Null => Ok(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuSignature {
    Rsassa(TpmsSignatureRsa),
    Rsapss(TpmsSignatureRsa),
    Ecdsa(TpmsSignatureEcc),
    Ecdaa(TpmsSignatureEcc),
    Sm2(TpmsSignatureEcc),
    Ecschnorr(TpmsSignatureEcc),
    Hmac(TpmtHa),
    Null,
}

impl TpmTagged for TpmuSignature {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmuSignature {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Rsassa(s) | Self::Rsapss(s) => s.len(),
            Self::Ecdsa(s) | Self::Ecdaa(s) | Self::Sm2(s) | Self::Ecschnorr(s) => s.len(),
            Self::Hmac(s) => s.len(),
            Self::Null => 0,
        }
    }
}

impl TpmBuild for TpmuSignature {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Rsassa(s) | Self::Rsapss(s) => s.build(writer),
            Self::Ecdsa(s) | Self::Ecdaa(s) | Self::Sm2(s) | Self::Ecschnorr(s) => s.build(writer),
            Self::Hmac(s) => s.build(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmParseTagged for TpmuSignature {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Rsassa => {
                let (val, buf) = TpmsSignatureRsa::parse(buf)?;
                Ok((Self::Rsassa(val), buf))
            }
            TpmAlgId::Rsapss => {
                let (val, buf) = TpmsSignatureRsa::parse(buf)?;
                Ok((Self::Rsapss(val), buf))
            }
            TpmAlgId::Ecdsa => {
                let (val, buf) = TpmsSignatureEcc::parse(buf)?;
                Ok((Self::Ecdsa(val), buf))
            }
            TpmAlgId::Ecdaa => {
                let (val, buf) = TpmsSignatureEcc::parse(buf)?;
                Ok((Self::Ecdaa(val), buf))
            }
            TpmAlgId::Sm2 => {
                let (val, buf) = TpmsSignatureEcc::parse(buf)?;
                Ok((Self::Sm2(val), buf))
            }
            TpmAlgId::Ecschnorr => {
                let (val, buf) = TpmsSignatureEcc::parse(buf)?;
                Ok((Self::Ecschnorr(val), buf))
            }
            TpmAlgId::Hmac => {
                let (val, buf) = TpmtHa::parse(buf)?;
                Ok((Self::Hmac(val), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuAttest {
    Certify(TpmsCertifyInfo),
    Creation(TpmsCreationInfo),
    Quote(TpmsQuoteInfo),
    CommandAudit(TpmsCommandAuditInfo),
    SessionAudit(TpmsSessionAuditInfo),
    Time(TpmsTimeAttestInfo),
    Nv(TpmsNvCertifyInfo),
    NvDigest(TpmsNvDigestCertifyInfo),
}

impl TpmTagged for TpmuAttest {
    type Tag = crate::data::TpmSt;
    type Value = ();
}

impl TpmSized for TpmuAttest {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Certify(i) => i.len(),
            Self::Creation(i) => i.len(),
            Self::Quote(i) => i.len(),
            Self::CommandAudit(i) => i.len(),
            Self::SessionAudit(i) => i.len(),
            Self::Time(i) => i.len(),
            Self::Nv(i) => i.len(),
            Self::NvDigest(i) => i.len(),
        }
    }
}

impl TpmBuild for TpmuAttest {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Certify(i) => i.build(writer),
            Self::Creation(i) => i.build(writer),
            Self::Quote(i) => i.build(writer),
            Self::CommandAudit(i) => i.build(writer),
            Self::SessionAudit(i) => i.build(writer),
            Self::Time(i) => i.build(writer),
            Self::Nv(i) => i.build(writer),
            Self::NvDigest(i) => i.build(writer),
        }
    }
}

impl TpmParseTagged for TpmuAttest {
    fn parse_tagged(tag: crate::data::TpmSt, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            crate::data::TpmSt::AttestCertify => {
                let (val, buf) = TpmsCertifyInfo::parse(buf)?;
                Ok((Self::Certify(val), buf))
            }
            crate::data::TpmSt::AttestCreation => {
                let (val, buf) = TpmsCreationInfo::parse(buf)?;
                Ok((Self::Creation(val), buf))
            }
            crate::data::TpmSt::AttestQuote => {
                let (val, buf) = TpmsQuoteInfo::parse(buf)?;
                Ok((Self::Quote(val), buf))
            }
            crate::data::TpmSt::AttestCommandAudit => {
                let (val, buf) = TpmsCommandAuditInfo::parse(buf)?;
                Ok((Self::CommandAudit(val), buf))
            }
            crate::data::TpmSt::AttestSessionAudit => {
                let (val, buf) = TpmsSessionAuditInfo::parse(buf)?;
                Ok((Self::SessionAudit(val), buf))
            }
            crate::data::TpmSt::AttestTime => {
                let (val, buf) = TpmsTimeAttestInfo::parse(buf)?;
                Ok((Self::Time(val), buf))
            }
            crate::data::TpmSt::AttestNv => {
                let (val, buf) = TpmsNvCertifyInfo::parse(buf)?;
                Ok((Self::Nv(val), buf))
            }
            crate::data::TpmSt::AttestNvDigest => {
                let (val, buf) = TpmsNvDigestCertifyInfo::parse(buf)?;
                Ok((Self::NvDigest(val), buf))
            }
            _ => Err(TpmErrorKind::InvalidTag {
                type_name: "TpmuAttest",
                expected: 0,
                got: tag as u16,
            }),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuKeyedhashScheme {
    Hmac(TpmsSchemeHash),
    Xor(TpmsSchemeXor),
    Null,
}

impl TpmTagged for TpmuKeyedhashScheme {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmuKeyedhashScheme {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Hmac(s) => s.len(),
            Self::Xor(s) => s.len(),
            Self::Null => 0,
        }
    }
}

impl TpmBuild for TpmuKeyedhashScheme {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Hmac(s) => s.build(writer),
            Self::Xor(s) => s.build(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmParseTagged for TpmuKeyedhashScheme {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Hmac => {
                let (val, buf) = TpmsSchemeHash::parse(buf)?;
                Ok((Self::Hmac(val), buf))
            }
            TpmAlgId::Xor => {
                let (val, buf) = TpmsSchemeXor::parse(buf)?;
                Ok((Self::Xor(val), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuSigScheme {
    Any(TpmsSchemeHash),
    Null,
}

impl TpmTagged for TpmuSigScheme {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmuSigScheme {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Any(s) => s.len(),
            Self::Null => 0,
        }
    }
}

impl TpmBuild for TpmuSigScheme {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Any(s) => s.build(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmParseTagged for TpmuSigScheme {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        if tag == TpmAlgId::Null {
            Ok((Self::Null, buf))
        } else {
            let (val, buf) = TpmsSchemeHash::parse(buf)?;
            Ok((Self::Any(val), buf))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuAsymScheme {
    Any(TpmsSchemeHash),
    Null,
}

impl TpmTagged for TpmuAsymScheme {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmuAsymScheme {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Any(s) => s.len(),
            Self::Null => 0,
        }
    }
}

impl TpmBuild for TpmuAsymScheme {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Any(s) => s.build(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmParseTagged for TpmuAsymScheme {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        if tag == TpmAlgId::Null {
            Ok((Self::Null, buf))
        } else {
            let (val, buf) = TpmsSchemeHash::parse(buf)?;
            Ok((Self::Any(val), buf))
        }
    }
}
