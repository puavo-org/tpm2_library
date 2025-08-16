// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

use crate::{
    data::{
        Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bMaxNvBuffer, Tpm2bName,
        Tpm2bNonce, Tpm2bSensitiveData, TpmAlgId, TpmCap, TpmEccCurve, TpmRh, TpmSt, TpmaAlgorithm,
        TpmaLocality, TpmaNv, TpmaSession, TpmiYesNo, TpmlPcrSelection, TpmtKdfScheme, TpmtScheme,
        TpmtSymDefObject, TpmuCapabilities,
    },
    tpm_struct, TpmBuffer, TpmBuild, TpmErrorKind, TpmParse, TpmParseTagged, TpmResult, TpmSized,
    TpmTagged, TpmWriter,
};
use core::{convert::TryFrom, mem::size_of, ops::Deref};

pub const TPM_PCR_SELECT_MAX: usize = 3;
pub type TpmsPcrSelect = TpmBuffer<TPM_PCR_SELECT_MAX>;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsAlgProperty {
        pub alg: TpmAlgId,
        pub alg_properties: TpmaAlgorithm,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsAuthCommand {
        pub session_handle: crate::TpmSession,
        pub nonce: Tpm2bNonce,
        pub session_attributes: TpmaSession,
        pub hmac: Tpm2bAuth,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsAuthResponse {
        pub nonce: Tpm2bNonce,
        pub session_attributes: TpmaSession,
        pub hmac: Tpm2bAuth,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TpmsCapabilityData {
    pub capability: TpmCap,
    pub data: TpmuCapabilities,
}

impl TpmTagged for TpmsCapabilityData {
    type Tag = TpmCap;
    type Value = ();
}

impl TpmSized for TpmsCapabilityData {
    const SIZE: usize = size_of::<u32>() + TpmuCapabilities::SIZE;
    fn len(&self) -> usize {
        self.capability.len() + self.data.len()
    }
}

impl TpmBuild for TpmsCapabilityData {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.capability.build(writer)?;
        self.data.build(writer)
    }
}

impl<'a> TpmParse<'a> for TpmsCapabilityData {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (capability, buf) = TpmCap::parse(buf)?;
        let (data, buf) = TpmuCapabilities::parse_tagged(capability, buf)?;
        Ok((Self { capability, data }, buf))
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsClockInfo {
        pub clock: u64,
        pub reset_count: u32,
        pub restart_count: u32,
        pub safe: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct TpmsContext {
        pub sequence: u64,
        pub saved_handle: crate::TpmTransient,
        pub hierarchy: TpmRh,
        pub context_blob: Tpm2b,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsCreationData {
        pub pcr_select: TpmlPcrSelection,
        pub pcr_digest: Tpm2bDigest,
        pub locality: TpmaLocality,
        pub parent_name_alg: TpmAlgId,
        pub parent_name: Tpm2bName,
        pub parent_qualified_name: Tpm2bName,
        pub outside_info: Tpm2bData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsEccPoint {
        pub x: Tpm2bEccParameter,
        pub y: Tpm2bEccParameter,
    }
}

tpm_struct! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct TpmsEmpty {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsKeyedhashParms {
        pub scheme: TpmtScheme,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsNvPublic {
        pub nv_index: u32,
        pub name_alg: TpmAlgId,
        pub attributes: TpmaNv,
        pub auth_policy: Tpm2bDigest,
        pub data_size: u16,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct TpmsPcrSelection {
    pub hash: TpmAlgId,
    pub pcr_select: TpmsPcrSelect,
}

impl TpmSized for TpmsPcrSelection {
    const SIZE: usize = TpmAlgId::SIZE + 1 + TPM_PCR_SELECT_MAX;

    fn len(&self) -> usize {
        self.hash.len() + 1 + self.pcr_select.deref().len()
    }
}

impl TpmBuild for TpmsPcrSelection {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.hash.build(writer)?;
        let size =
            u8::try_from(self.pcr_select.deref().len()).map_err(|_| TpmErrorKind::ValueTooLarge)?;
        size.build(writer)?;
        writer.write_bytes(&self.pcr_select)
    }
}

impl<'a> TpmParse<'a> for TpmsPcrSelection {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (hash, buf) = TpmAlgId::parse(buf)?;
        let (size, buf) = u8::parse(buf)?;
        let size = size as usize;

        if size > TPM_PCR_SELECT_MAX {
            return Err(TpmErrorKind::ValueTooLarge);
        }
        if buf.len() < size {
            return Err(TpmErrorKind::Boundary);
        }

        let (pcr_bytes, buf) = buf.split_at(size);
        let pcr_select = TpmBuffer::try_from(pcr_bytes)?;

        Ok((Self { hash, pcr_select }, buf))
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsSensitiveCreate {
        pub user_auth: Tpm2bAuth,
        pub data: Tpm2bSensitiveData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsIdObject {
        pub integrity_hmac: Tpm2bDigest,
        pub enc_identity: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsSymcipherParms {
        pub sym: TpmtSymDefObject,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsTimeInfo {
        pub time: u64,
        pub clock_info: TpmsClockInfo,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsSignatureRsa {
        pub hash: TpmAlgId,
        pub sig: crate::data::Tpm2bPublicKeyRsa,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsSignatureEcc {
        pub hash: TpmAlgId,
        pub signature_r: Tpm2bEccParameter,
        pub signature_s: Tpm2bEccParameter,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsTimeAttestInfo {
        pub time: TpmsTimeInfo,
        pub firmware_version: u64,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsCertifyInfo {
        pub name: Tpm2bName,
        pub qualified_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsQuoteInfo {
        pub pcr_select: TpmlPcrSelection,
        pub pcr_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsCommandAuditInfo {
        pub audit_counter: u64,
        pub digest_alg: TpmAlgId,
        pub audit_digest: Tpm2bDigest,
        pub command_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    pub struct TpmsSessionAuditInfo {
        pub exclusive_session: TpmiYesNo,
        pub session_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsCreationInfo {
        pub object_name: Tpm2bName,
        pub creation_hash: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsNvCertifyInfo {
        pub index_name: Tpm2bName,
        pub offset: u16,
        pub nv_contents: Tpm2bMaxNvBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmsNvDigestCertifyInfo {
        pub index_name: Tpm2bName,
        pub nv_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmsAlgorithmDetailEcc {
        pub curve_id: TpmEccCurve,
        pub key_size: u16,
        pub kdf: TpmtKdfScheme,
        pub sign: TpmtScheme,
        pub p: Tpm2bEccParameter,
        pub a: Tpm2bEccParameter,
        pub b: Tpm2bEccParameter,
        pub gx: Tpm2bEccParameter,
        pub gy: Tpm2bEccParameter,
        pub n: Tpm2bEccParameter,
        pub h: Tpm2bEccParameter,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TpmsAttest {
    pub magic: u32,
    pub attest_type: TpmSt,
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub attested: crate::data::TpmuAttest,
}

impl TpmTagged for TpmsAttest {
    type Tag = TpmSt;
    type Value = crate::data::TpmuAttest;
}

impl TpmSized for TpmsAttest {
    const SIZE: usize = size_of::<u32>()
        + TpmSt::SIZE
        + Tpm2bName::SIZE
        + Tpm2bData::SIZE
        + TpmsClockInfo::SIZE
        + size_of::<u64>()
        + crate::data::TpmuAttest::SIZE;
    fn len(&self) -> usize {
        size_of::<u32>()
            + self.attest_type.len()
            + self.qualified_signer.len()
            + self.extra_data.len()
            + self.clock_info.len()
            + size_of::<u64>()
            + self.attested.len()
    }
}

impl TpmBuild for TpmsAttest {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        0xff54_4347_u32.build(writer)?;
        self.attest_type.build(writer)?;
        self.qualified_signer.build(writer)?;
        self.extra_data.build(writer)?;
        self.clock_info.build(writer)?;
        self.firmware_version.build(writer)?;
        self.attested.build(writer)
    }
}

impl<'a> TpmParse<'a> for TpmsAttest {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        let (magic, buf) = u32::parse(buf)?;
        if magic != 0xff54_4347 {
            return Err(TpmErrorKind::InvalidMagic {
                expected: 0xff54_4347,
                got: magic,
            });
        }
        let (attest_type, buf) = TpmSt::parse(buf)?;
        let (qualified_signer, buf) = Tpm2bName::parse(buf)?;
        let (extra_data, buf) = Tpm2bData::parse(buf)?;
        let (clock_info, buf) = TpmsClockInfo::parse(buf)?;
        let (firmware_version, buf) = u64::parse(buf)?;
        let (attested, buf) = crate::data::TpmuAttest::parse_tagged(attest_type, buf)?;

        Ok((
            Self {
                magic,
                attest_type,
                qualified_signer,
                extra_data,
                clock_info,
                firmware_version,
                attested,
            },
            buf,
        ))
    }
}
