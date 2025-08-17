// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    data::{
        Tpm2b, Tpm2bAttest, Tpm2bAuth, Tpm2bCreationData, Tpm2bData, Tpm2bDigest, Tpm2bEccPoint,
        Tpm2bEncryptedSecret, Tpm2bIdObject, Tpm2bMaxBuffer, Tpm2bMaxNvBuffer, Tpm2bName,
        Tpm2bNvPublic, Tpm2bPrivate, Tpm2bPublic, Tpm2bPublicKeyRsa, Tpm2bSensitive,
        Tpm2bSensitiveCreate, Tpm2bSensitiveData, Tpm2bTimeout, TpmAlgId, TpmCap, TpmCc,
        TpmEccCurve, TpmRc, TpmRh, TpmSe, TpmSt, TpmSu, TpmaLocality, TpmiYesNo, TpmlAlg,
        TpmlDigest, TpmlDigestValues, TpmlPcrSelection, TpmsAlgorithmDetailEcc, TpmsAuthCommand,
        TpmsAuthResponse, TpmsCapabilityData, TpmsContext, TpmtRsaDecrypt, TpmtSignature,
        TpmtSymDef, TpmtSymDefObject, TpmtTkAuth, TpmtTkCreation, TpmtTkHashcheck, TpmtTkVerified,
    },
    tpm_dispatch, tpm_response, tpm_struct, TpmBuild, TpmErrorKind, TpmList, TpmParse,
    TpmPersistent, TpmResult, TpmSession, TpmSized, TpmTransient, TpmWriter,
};
use core::{convert::TryFrom, fmt::Debug, mem::size_of};

/// The maximum number of handles a command can have.
pub const MAX_HANDLES: usize = 8;
/// The maximum number of sessions a command can have.
pub const MAX_SESSIONS: usize = 8;

/// A fixed-capacity list for TPM handles.
pub type TpmHandles = TpmList<u32, MAX_HANDLES>;
/// A fixed-capacity list for command authorization sessions.
pub type TpmAuthCommands = TpmList<TpmsAuthCommand, MAX_SESSIONS>;
/// A fixed-capacity list for response authorization sessions.
pub type TpmAuthResponses = TpmList<TpmsAuthResponse, MAX_SESSIONS>;

/// A trait for TPM commands and responses that provides header information.
pub trait TpmHeader<'a>: TpmBuild + TpmParse<'a> + Debug + TpmSized {
    const COMMAND: TpmCc;
    const NO_SESSIONS: bool;
    const WITH_SESSIONS: bool;
    const HANDLES: usize;
}

/// The result of parsing a TPM response, containing either the successfully parsed
/// body and auth areas (with a success or warning code) or a fatal error code.
pub type TpmParseResult<'a> = Result<(TpmRc, TpmResponseBody, TpmAuthResponses), (TpmRc, &'a [u8])>;

pub const TPM_HEADER_SIZE: usize = 10;

/// Builds a TPM command into a writer and returns the total bytes written.
///
/// # Errors
///
/// * `TpmErrorKind::ValueTooLarge` if the command has unknown state
pub fn tpm_build_command<'a, C>(
    command: &C,
    tag: TpmSt,
    handles: Option<&[u32]>,
    sessions: &[TpmsAuthCommand],
    writer: &mut crate::TpmWriter,
) -> TpmResult<()>
where
    C: TpmHeader<'a>,
{
    match tag {
        TpmSt::NoSessions => {
            if !C::NO_SESSIONS {
                return Err(TpmErrorKind::InvalidTag {
                    type_name: "TpmSt",
                    expected: TpmSt::Sessions as u16,
                    got: tag as u16,
                });
            }
        }
        TpmSt::Sessions => {
            if !C::WITH_SESSIONS {
                return Err(TpmErrorKind::InvalidTag {
                    type_name: "TpmSt",
                    expected: TpmSt::NoSessions as u16,
                    got: tag as u16,
                });
            }
        }
        _ => {
            return Err(TpmErrorKind::InvalidValue);
        }
    }

    let handles = handles.unwrap_or(&[]);
    if handles.len() != C::HANDLES {
        return Err(TpmErrorKind::InternalError);
    }

    let handle_area_len = core::mem::size_of_val(handles);
    let parameters_len = command.len();

    let auth_area_len = if tag == TpmSt::Sessions {
        let sessions_len: usize = sessions.iter().map(TpmSized::len).sum();
        size_of::<u32>() + sessions_len
    } else {
        0
    };

    let total_body_len = handle_area_len + auth_area_len + parameters_len;
    let command_size =
        u32::try_from(TPM_HEADER_SIZE + total_body_len).map_err(|_| TpmErrorKind::ValueTooLarge)?;

    (tag as u16).build(writer)?;
    command_size.build(writer)?;
    (C::COMMAND as u32).build(writer)?;

    for handle in handles {
        handle.build(writer)?;
    }

    if tag == TpmSt::Sessions {
        let sessions_len_u32 = u32::try_from(auth_area_len - size_of::<u32>())
            .map_err(|_| TpmErrorKind::ValueTooLarge)?;
        sessions_len_u32.build(writer)?;
        for s in sessions {
            s.build(writer)?;
        }
    }

    command.build(writer)
}

/// Builds a TPM response.
///
/// # Errors
///
/// * `TpmErrorKind::ValueTooLarge` if the response has unknown state
pub fn tpm_build_response<R>(
    response: &R,
    sessions: &[TpmsAuthResponse],
    rc: TpmRc,
    writer: &mut crate::TpmWriter,
) -> TpmResult<()>
where
    R: for<'a> TpmHeader<'a>,
{
    let tag = if !rc.is_error() && R::WITH_SESSIONS && !sessions.is_empty() {
        TpmSt::Sessions
    } else {
        TpmSt::NoSessions
    };

    if rc.is_error() {
        (TpmSt::NoSessions as u16).build(writer)?;
        u32::try_from(TPM_HEADER_SIZE)?.build(writer)?;
        rc.value().build(writer)?;
        return Ok(());
    }

    let body_len = response.len();
    let sessions_len: usize = sessions.iter().map(TpmSized::len).sum();
    let total_body_len = body_len + sessions_len;
    let response_size =
        u32::try_from(TPM_HEADER_SIZE + total_body_len).map_err(|_| TpmErrorKind::ValueTooLarge)?;

    (tag as u16).build(writer)?;
    response_size.build(writer)?;
    rc.value().build(writer)?;

    response.build(writer)?;

    if tag == TpmSt::Sessions {
        for s in sessions {
            s.build(writer)?;
        }
    }
    Ok(())
}

/// Parses a command from a TPM command buffer.
///
/// # Errors
///
/// * `TpmErrorKind::Boundary` if the buffer is too small
/// * `TpmErrorKind::InvalidDiscriminant` if the buffer contains an unsupported command code or unexpected byte
/// * `TpmErrorKind::TrailingData` if the command has after spurious data left
pub fn tpm_parse_command(buf: &[u8]) -> TpmResult<(TpmHandles, TpmCommandBody, TpmAuthCommands)> {
    if buf.len() < TPM_HEADER_SIZE {
        return Err(TpmErrorKind::Boundary);
    }
    let command_len = buf.len();

    let (tag_raw, buf) = u16::parse(buf)?;
    let tag = TpmSt::try_from(tag_raw).map_err(|()| TpmErrorKind::InvalidDiscriminant {
        type_name: "TpmSt",
        value: u64::from(tag_raw),
    })?;
    let (size, buf) = u32::parse(buf)?;
    let (cc_raw, mut buf) = u32::parse(buf)?;

    if command_len != size as usize {
        return Err(TpmErrorKind::Boundary);
    }

    let cc = TpmCc::try_from(cc_raw).map_err(|()| TpmErrorKind::InvalidDiscriminant {
        type_name: "TpmCc",
        value: u64::from(cc_raw),
    })?;
    let dispatch = PARSE_COMMAND_MAP
        .binary_search_by_key(&cc, |d| d.0)
        .map(|index| &PARSE_COMMAND_MAP[index])
        .map_err(|_| TpmErrorKind::InvalidDiscriminant {
            type_name: "TpmCc",
            value: u64::from(cc_raw),
        })?;

    if tag == TpmSt::Sessions && !dispatch.2 {
        return Err(TpmErrorKind::InvalidTag {
            type_name: "TpmSt",
            expected: TpmSt::NoSessions as u16,
            got: tag_raw,
        });
    }
    if tag == TpmSt::NoSessions && !dispatch.1 {
        return Err(TpmErrorKind::InvalidTag {
            type_name: "TpmSt",
            expected: TpmSt::Sessions as u16,
            got: tag_raw,
        });
    }

    let mut handles = TpmHandles::new();
    for _ in 0..dispatch.3 {
        let (handle, rest) = u32::parse(buf)?;
        handles
            .try_push(handle)
            .map_err(|_| TpmErrorKind::ValueTooLarge)?;
        buf = rest;
    }

    let mut sessions = TpmAuthCommands::new();
    let param_buf = if tag == TpmSt::Sessions {
        let (auth_area_size, auth_buf) = u32::parse(buf)?;
        let auth_area_size = auth_area_size as usize;
        if auth_buf.len() < auth_area_size {
            return Err(TpmErrorKind::Boundary);
        }
        let (mut auth_area, param_buf) = auth_buf.split_at(auth_area_size);
        while !auth_area.is_empty() {
            let (session, rest) = TpmsAuthCommand::parse(auth_area)?;
            sessions
                .try_push(session)
                .map_err(|_| TpmErrorKind::ValueTooLarge)?;
            auth_area = rest;
        }
        if !auth_area.is_empty() {
            return Err(TpmErrorKind::TrailingData);
        }
        param_buf
    } else {
        buf
    };

    let (command_data, remainder) = (dispatch.4)(param_buf)?;

    if !remainder.is_empty() {
        return Err(TpmErrorKind::TrailingData);
    }

    Ok((handles, command_data, sessions))
}

/// Parses a response from a TPM response buffer.
///
/// # Errors
///
/// * `TpmErrorKind::Boundary` if the buffer is too small
/// * `TpmErrorKind::InvalidTag` if the tag in the buffer does not match expected
/// * `TpmErrorKind::InvalidDiscriminant` if the buffer contains an unsupported command code
/// * `TpmErrorKind::TrailingData` if the response has after spurious data left
pub fn tpm_parse_response(cc: TpmCc, buf: &[u8]) -> TpmResult<TpmParseResult<'_>> {
    if buf.len() < TPM_HEADER_SIZE {
        return Err(TpmErrorKind::Boundary);
    }

    let (tag_raw, remainder) = u16::parse(buf)?;
    let (size, remainder) = u32::parse(remainder)?;
    let (code, body_buf) = u32::parse(remainder)?;

    if buf.len() != size as usize {
        return Err(TpmErrorKind::Boundary);
    }

    let rc = TpmRc::try_from(code)?;
    if rc.is_error() {
        return Ok(Err((rc, body_buf)));
    }

    let tag = TpmSt::try_from(tag_raw).map_err(|()| TpmErrorKind::InvalidDiscriminant {
        type_name: "TpmSt",
        value: u64::from(tag_raw),
    })?;

    let dispatch = PARSE_RESPONSE_MAP
        .binary_search_by_key(&cc, |d| d.0)
        .map(|index| &PARSE_RESPONSE_MAP[index])
        .map_err(|_| TpmErrorKind::InvalidDiscriminant {
            type_name: "TpmCc",
            value: u64::from(cc as u32),
        })?;

    let (body, mut session_area) = (dispatch.2)(body_buf)?;

    let mut auth_responses = TpmAuthResponses::new();
    if tag == TpmSt::Sessions {
        while !session_area.is_empty() {
            let (session, rest) = TpmsAuthResponse::parse(session_area)?;
            auth_responses
                .try_push(session)
                .map_err(|_| TpmErrorKind::ValueTooLarge)?;
            session_area = rest;
        }
    }

    if !session_area.is_empty() {
        return Err(TpmErrorKind::TrailingData);
    }

    Ok(Ok((rc, body, auth_responses)))
}

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmStartupCommand,
    TpmCc::Startup,
    true,
    false,
    0,
    {
        pub startup_type: TpmSu,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmStartupResponse,
    TpmCc::Startup,
    true,
    false,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmShutdownCommand,
    TpmCc::Shutdown,
    true,
    true,
    0,
    {
        pub shutdown_type: TpmSu,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmShutdownResponse,
    TpmCc::Shutdown,
    true,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmContextLoadCommand,
    TpmCc::ContextLoad,
    true,
    false,
    0,
    {
        pub context: TpmsContext,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmContextSaveCommand,
    TpmCc::ContextSave,
    true,
    false,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmDictionaryAttackLockResetCommand,
    TpmCc::DictionaryAttackLockReset,
    false,
    true,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmFlushContextCommand,
    TpmCc::FlushContext,
    true,
    false,
    0,
    {
        pub flush_handle: u32,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmUnsealCommand,
    TpmCc::Unseal,
    false,
    true,
    1,
    {}
);

macro_rules! tpm_create {
	($name:ident, $cc:expr) => {
		tpm_struct!(
			#[derive(Debug, Default, PartialEq, Eq, Clone)]
			$name,
			$cc,
			false,
			true,
			1,
			{
				pub in_sensitive: Tpm2bSensitiveCreate,
				pub in_public: Tpm2bPublic,
				pub outside_info: Tpm2b,
				pub creation_pcr: TpmlPcrSelection,
			}
		);
	};
}

tpm_create!(TpmCreateCommand, TpmCc::Create);
tpm_create!(TpmCreatePrimaryCommand, TpmCc::CreatePrimary);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEvictControlCommand,
    TpmCc::EvictControl,
    false,
    true,
    2,
    {
        pub persistent_handle: TpmPersistent,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetCapabilityCommand,
    TpmCc::GetCapability,
    true,
    true,
    0,
    {
        pub cap: TpmCap,
        pub property: u32,
        pub property_count: u32,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHashCommand,
    TpmCc::Hash,
    true,
    false,
    0,
    {
        pub data: Tpm2bMaxBuffer,
        pub hash_alg: TpmAlgId,
        pub hierarchy: TpmRh,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmImportCommand,
    TpmCc::Import,
    false,
    true,
    1,
    {
        pub encryption_key: Tpm2b,
        pub object_public: Tpm2bPublic,
        pub duplicate: Tpm2bPrivate,
        pub in_sym_seed: Tpm2bEncryptedSecret,
        pub symmetric_alg: TpmtSymDef,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmLoadCommand,
    TpmCc::Load,
    false,
    true,
    1,
    {
        pub in_private: Tpm2bPrivate,
        pub in_public: Tpm2bPublic,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmObjectChangeAuthCommand,
    TpmCc::ObjectChangeAuth,
    false,
    true,
    2,
    {
        pub new_auth: Tpm2bAuth,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrEventCommand,
    TpmCc::PcrEvent,
    false,
    true,
    1,
    {
        pub event_data: Tpm2b,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPcrReadCommand,
    TpmCc::PcrRead,
    true,
    false,
    0,
    {
        pub pcr_selection_in: TpmlPcrSelection,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyAuthValueCommand,
    TpmCc::PolicyAuthValue,
    false,
    true,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyCommandCodeCommand,
    TpmCc::PolicyCommandCode,
    false,
    true,
    1,
    {
        pub code: TpmCc,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyGetDigestCommand,
    TpmCc::PolicyGetDigest,
    false,
    true,
    1,
    {}
);

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TpmPolicyGetDigestResponse {
    pub policy_digest: Tpm2bDigest,
}
impl TpmHeader<'_> for TpmPolicyGetDigestResponse {
    const COMMAND: TpmCc = TpmCc::PolicyGetDigest;
    const NO_SESSIONS: bool = false;
    const WITH_SESSIONS: bool = true;
    const HANDLES: usize = 0;
}
impl TpmSized for TpmPolicyGetDigestResponse {
    const SIZE: usize = <Tpm2bDigest>::SIZE;
    fn len(&self) -> usize {
        self.policy_digest.len()
    }
}
impl TpmBuild for TpmPolicyGetDigestResponse {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.policy_digest.build(writer)
    }
}
impl<'a> TpmParse<'a> for TpmPolicyGetDigestResponse {
    fn parse(buf: &'a [u8]) -> TpmResult<(Self, &'a [u8])> {
        if buf.is_empty() {
            return Ok((Self::default(), buf));
        }
        let (policy_digest, buf) = Tpm2bDigest::parse(buf)?;
        Ok((Self { policy_digest }, buf))
    }
}

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPolicyOrCommand,
    TpmCc::PolicyOR,
    false,
    true,
    1,
    {
        pub p_hash_list: TpmlDigest,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyPasswordCommand,
    TpmCc::PolicyPassword,
    false,
    true,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPolicyPcrCommand,
    TpmCc::PolicyPcr,
    false,
    true,
    1,
    {
        pub pcr_digest: Tpm2bDigest,
        pub pcrs: TpmlPcrSelection,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyRestartCommand,
    TpmCc::PolicyRestart,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPolicySecretCommand,
    TpmCc::PolicySecret,
    false,
    true,
    2,
    {
        pub nonce_tpm: Tpm2b,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: Tpm2b,
        pub expiration: i32,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmReadPublicCommand,
    TpmCc::ReadPublic,
    true,
    true,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmStartAuthSessionCommand,
    TpmCc::StartAuthSession,
    true,
    true,
    2,
    {
        pub nonce_caller: Tpm2b,
        pub encrypted_salt: Tpm2b,
        pub session_type: TpmSe,
        pub symmetric: TpmtSymDefObject,
        pub auth_hash: TpmAlgId,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmVendorTcgTestCommand,
    TpmCc::VendorTcgTest,
    true,
    false,
    0,
    {
        pub input_data: Tpm2bData,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmContextLoadResponse,
    TpmCc::ContextLoad,
    true,
    false,
    0,
    {
        pub loaded_handle: TpmTransient,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmContextSaveResponse,
    TpmCc::ContextSave,
    true,
    false,
    0,
    {
        pub context: TpmsContext,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHashResponse,
    TpmCc::Hash,
    true,
    false,
    0,
    {
        pub out_hash: Tpm2bDigest,
        pub validation: TpmtTkHashcheck,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmImportResponse,
    TpmCc::Import,
    false,
    true,
    0,
    {
        pub out_private: Tpm2bPrivate,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmObjectChangeAuthResponse,
    TpmCc::ObjectChangeAuth,
    false,
    true,
    {
        pub out_private: Tpm2bPrivate,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPcrReadResponse,
    TpmCc::PcrRead,
    true,
    false,
    0,
    {
        pub pcr_update_counter: u32,
        pub pcr_selection_out: TpmlPcrSelection,
        pub pcr_values: TpmlDigest,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyAuthValueResponse,
    TpmCc::PolicyAuthValue,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyCommandCodeResponse,
    TpmCc::PolicyCommandCode,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyOrResponse,
    TpmCc::PolicyOR,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyPasswordResponse,
    TpmCc::PolicyPassword,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyPcrResponse,
    TpmCc::PolicyPcr,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyRestartResponse,
    TpmCc::PolicyRestart,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicySecretResponse,
    TpmCc::PolicySecret,
    false,
    true,
    0,
    {}
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmReadPublicResponse,
    TpmCc::ReadPublic,
    true,
    false,
    {
        pub out_public: Tpm2bPublic,
        pub name: Tpm2bName,
        pub qualified_name: Tpm2bName,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmStartAuthSessionResponse,
    TpmCc::StartAuthSession,
    true,
    false,
    0,
    {
        pub session_handle: TpmSession,
        pub nonce_tpm: Tpm2b,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmVendorTcgTestResponse,
    TpmCc::VendorTcgTest,
    true,
    false,
    0,
    {
        pub output_data: Tpm2bData,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCreatePrimaryResponse,
    TpmCc::CreatePrimary,
    false,
    true,
    pub object_handle: TpmTransient,
    {
        pub out_public: Tpm2bPublic,
        pub creation_data: Tpm2bCreationData,
        pub creation_hash: Tpm2bDigest,
        pub creation_ticket: TpmtTkCreation,
        pub name: Tpm2bName,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCreateResponse,
    TpmCc::Create,
    false,
    true,
    {
        pub out_private: Tpm2bPrivate,
        pub out_public: Tpm2bPublic,
        pub creation_data: Tpm2bCreationData,
        pub creation_hash: Tpm2bDigest,
        pub creation_ticket: TpmtTkCreation,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmDictionaryAttackLockResetResponse,
    TpmCc::DictionaryAttackLockReset,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmEvictControlResponse,
    TpmCc::EvictControl,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmFlushContextResponse,
    TpmCc::FlushContext,
    true,
    false,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetCapabilityResponse,
    TpmCc::GetCapability,
    true,
    false,
    0,
    {
        pub more_data: TpmiYesNo,
        pub capability_data: TpmsCapabilityData,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmLoadResponse,
    TpmCc::Load,
    false,
    true,
    pub object_handle: TpmTransient,
    {
        pub name: Tpm2bName,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPcrEventResponse,
    TpmCc::PcrEvent,
    false,
    true,
    {
        pub digests: TpmlDigestValues,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmUnsealResponse,
    TpmCc::Unseal,
    false,
    true,
    {
        pub out_data: Tpm2b,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvDefineSpaceCommand,
    TpmCc::NvDefineSpace,
    false,
    true,
    1,
    {
        pub auth: Tpm2bAuth,
        pub public_info: Tpm2bNvPublic,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvDefineSpaceResponse,
    TpmCc::NvDefineSpace,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmNvUndefineSpaceCommand,
    TpmCc::NvUndefineSpace,
    false,
    true,
    2,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvUndefineSpaceResponse,
    TpmCc::NvUndefineSpace,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmNvUndefineSpaceSpecialCommand,
    TpmCc::NvUndefineSpaceSpecial,
    false,
    true,
    2,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvUndefineSpaceSpecialResponse,
    TpmCc::NvUndefineSpaceSpecial,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmNvReadPublicCommand,
    TpmCc::NvReadPublic,
    true,
    false,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvReadPublicResponse,
    TpmCc::NvReadPublic,
    true,
    false,
    0,
    {
        pub nv_public: Tpm2bNvPublic,
        pub nv_name: Tpm2bName,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvWriteCommand,
    TpmCc::NvWrite,
    false,
    true,
    2,
    {
        pub data: Tpm2bMaxNvBuffer,
        pub offset: u16,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvWriteResponse,
    TpmCc::NvWrite,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvIncrementCommand,
    TpmCc::NvIncrement,
    false,
    true,
    2,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvIncrementResponse,
    TpmCc::NvIncrement,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvExtendCommand,
    TpmCc::NvExtend,
    false,
    true,
    2,
    {
        pub data: Tpm2bMaxNvBuffer,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvExtendResponse,
    TpmCc::NvExtend,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmNvSetBitsCommand,
    TpmCc::NvSetBits,
    false,
    true,
    2,
    {
        pub bits: u64,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvSetBitsResponse,
    TpmCc::NvSetBits,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvWriteLockCommand,
    TpmCc::NvWriteLock,
    false,
    true,
    2,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvWriteLockResponse,
    TpmCc::NvWriteLock,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvGlobalWriteLockCommand,
    TpmCc::NvGlobalWriteLock,
    false,
    true,
    1,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvGlobalWriteLockResponse,
    TpmCc::NvGlobalWriteLock,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmNvReadCommand,
    TpmCc::NvRead,
    false,
    true,
    2,
    {
        pub size: u16,
        pub offset: u16,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmNvReadResponse,
    TpmCc::NvRead,
    false,
    true,
    0,
    {
        pub data: Tpm2bMaxNvBuffer,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvReadLockCommand,
    TpmCc::NvReadLock,
    false,
    true,
    2,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvReadLockResponse,
    TpmCc::NvReadLock,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvChangeAuthCommand,
    TpmCc::NvChangeAuth,
    false,
    true,
    1,
    {
        pub new_auth: Tpm2bAuth,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmNvChangeAuthResponse,
    TpmCc::NvChangeAuth,
    false,
    true,
    0,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvCertifyCommand,
    TpmCc::NvCertify,
    false,
    true,
    3,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
        pub size: u16,
        pub offset: u16,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmNvCertifyResponse,
    TpmCc::NvCertify,
    false,
    true,
    0,
    {
        pub certify_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCertifyCommand,
    TpmCc::Certify,
    false,
    true,
    2,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCertifyResponse,
    TpmCc::Certify,
    false,
    true,
    {
        pub certify_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCertifyCreationCommand,
    TpmCc::CertifyCreation,
    false,
    true,
    2,
    {
        pub qualifying_data: Tpm2bData,
        pub creation_hash: Tpm2bDigest,
        pub in_scheme: TpmtSignature,
        pub creation_ticket: TpmtTkCreation,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmCertifyCreationResponse,
    TpmCc::CertifyCreation,
    false,
    true,
    {
        pub certify_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmQuoteCommand,
    TpmCc::Quote,
    false,
    true,
    1,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
        pub pcr_select: TpmlPcrSelection,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmQuoteResponse,
    TpmCc::Quote,
    false,
    true,
    {
        pub quoted: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetSessionAuditDigestCommand,
    TpmCc::GetSessionAuditDigest,
    false,
    true,
    3,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetSessionAuditDigestResponse,
    TpmCc::GetSessionAuditDigest,
    false,
    true,
    {
        pub audit_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetCommandAuditDigestCommand,
    TpmCc::GetCommandAuditDigest,
    false,
    true,
    2,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetCommandAuditDigestResponse,
    TpmCc::GetCommandAuditDigest,
    false,
    true,
    {
        pub audit_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetTimeCommand,
    TpmCc::GetTime,
    false,
    true,
    2,
    {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetTimeResponse,
    TpmCc::GetTime,
    false,
    true,
    {
        pub time_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSignCommand,
    TpmCc::Sign,
    false,
    true,
    1,
    {
        pub digest: Tpm2bDigest,
        pub in_scheme: TpmtSignature,
        pub validation: TpmtTkHashcheck,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSignResponse,
    TpmCc::Sign,
    false,
    true,
    {
        pub signature: TpmtSignature,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmVerifySignatureCommand,
    TpmCc::VerifySignature,
    true,
    false,
    1,
    {
        pub digest: Tpm2bDigest,
        pub signature: TpmtSignature,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmVerifySignatureResponse,
    TpmCc::VerifySignature,
    true,
    false,
    {
        pub validation: TpmtTkVerified,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmMakeCredentialCommand,
    TpmCc::MakeCredential,
    true,
    true,
    1,
    {
        pub credential: Tpm2bDigest,
        pub object_name: Tpm2bName,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmMakeCredentialResponse,
    TpmCc::MakeCredential,
    true,
    true,
    {
        pub credential_blob: Tpm2bIdObject,
        pub secret: Tpm2bEncryptedSecret,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmLoadExternalCommand,
    TpmCc::LoadExternal,
    true,
    true,
    0,
    {
        pub in_private: Tpm2bSensitive,
        pub in_public: Tpm2bPublic,
        pub hierarchy: TpmRh,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmLoadExternalResponse,
    TpmCc::LoadExternal,
    true,
    true,
    pub object_handle: TpmTransient,
    {
        pub name: Tpm2bName,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmActivateCredentialCommand,
    TpmCc::ActivateCredential,
    true,
    true,
    2,
    {
        pub credential_blob: Tpm2bIdObject,
        pub secret: Tpm2bEncryptedSecret,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmActivateCredentialResponse,
    TpmCc::ActivateCredential,
    true,
    true,
    {
        pub cert_info: Tpm2bDigest,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSelfTestCommand,
    TpmCc::SelfTest,
    true,
    true,
    0,
    {
        pub full_test: TpmiYesNo,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmSelfTestResponse,
    TpmCc::SelfTest,
    true,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmIncrementalSelfTestCommand,
    TpmCc::IncrementalSelfTest,
    true,
    true,
    0,
    {
        pub to_test: TpmlAlg,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmIncrementalSelfTestResponse,
    TpmCc::IncrementalSelfTest,
    true,
    true,
    {
        pub to_do_list: TpmlAlg,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmGetTestResultCommand,
    TpmCc::GetTestResult,
    true,
    true,
    0,
    {}
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmGetTestResultResponse,
    TpmCc::GetTestResult,
    true,
    true,
    {
        pub out_data: Tpm2bMaxBuffer,
        pub test_result: TpmRc,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmDuplicateCommand,
    TpmCc::Duplicate,
    false,
    true,
    2,
    {
        pub encryption_key_in: Tpm2bData,
        pub symmetric_alg: TpmtSymDefObject,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmDuplicateResponse,
    TpmCc::Duplicate,
    false,
    true,
    {
        pub encryption_key_out: Tpm2bData,
        pub duplicate: Tpm2bPrivate,
        pub out_sym_seed: Tpm2bEncryptedSecret,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRewrapCommand,
    TpmCc::Rewrap,
    false,
    true,
    2,
    {
        pub in_duplicate: Tpm2bPrivate,
        pub name: Tpm2bName,
        pub in_sym_seed: Tpm2bEncryptedSecret,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRewrapResponse,
    TpmCc::Rewrap,
    false,
    true,
    {
        pub out_duplicate: Tpm2bPrivate,
        pub out_sym_seed: Tpm2bEncryptedSecret,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRsaEncryptCommand,
    TpmCc::RsaEncrypt,
    true,
    true,
    1,
    {
        pub message: Tpm2bPublicKeyRsa,
        pub in_scheme: TpmtRsaDecrypt,
        pub label: Tpm2bData,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRsaEncryptResponse,
    TpmCc::RsaEncrypt,
    true,
    true,
    {
        pub out_data: Tpm2bPublicKeyRsa,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRsaDecryptCommand,
    TpmCc::RsaDecrypt,
    false,
    true,
    1,
    {
        pub cipher_text: Tpm2bPublicKeyRsa,
        pub in_scheme: TpmtRsaDecrypt,
        pub label: Tpm2bData,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmRsaDecryptResponse,
    TpmCc::RsaDecrypt,
    false,
    true,
    {
        pub message: Tpm2bPublicKeyRsa,
    }
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmEcdhKeyGenCommand,
    TpmCc::EcdhKeyGen,
    true,
    true,
    1,
    {}
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEcdhKeyGenResponse,
    TpmCc::EcdhKeyGen,
    true,
    true,
    {
        pub z_point: Tpm2bEccPoint,
        pub pub_point: Tpm2bEccPoint,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmEcdhZGenCommand,
    TpmCc::EcdhZGen,
    false,
    true,
    1,
    {
        pub in_point: Tpm2bEccPoint,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEcdhZGenResponse,
    TpmCc::EcdhZGen,
    false,
    true,
    {
        pub out_point: Tpm2bEccPoint,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmEccParametersCommand,
    TpmCc::EccParameters,
    true,
    true,
    0,
    {
        pub curve_id: TpmEccCurve,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEccParametersResponse,
    TpmCc::EccParameters,
    true,
    true,
    {
        pub parameters: TpmsAlgorithmDetailEcc,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEncryptDecrypt2Command,
    TpmCc::EncryptDecrypt2,
    false,
    true,
    1,
    {
        pub in_data: Tpm2bMaxBuffer,
        pub decrypt: TpmiYesNo,
        pub mode: TpmAlgId,
        pub iv_in: Tpm2b,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEncryptDecrypt2Response,
    TpmCc::EncryptDecrypt2,
    false,
    true,
    {
        pub out_data: Tpm2bMaxBuffer,
        pub iv_out: Tpm2b,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmGetRandomCommand,
    TpmCc::GetRandom,
    true,
    true,
    0,
    {
        pub bytes_requested: u16,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmGetRandomResponse,
    TpmCc::GetRandom,
    true,
    true,
    {
        pub random_bytes: Tpm2bDigest,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmStirRandomCommand,
    TpmCc::StirRandom,
    true,
    true,
    0,
    {
        pub in_data: Tpm2bSensitiveData,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmStirRandomResponse,
    TpmCc::StirRandom,
    true,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHashSequenceStartCommand,
    TpmCc::HashSequenceStart,
    true,
    true,
    0,
    {
        pub auth: Tpm2bAuth,
        pub hash_alg: TpmAlgId,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    TpmHashSequenceStartResponse,
    TpmCc::HashSequenceStart,
    true,
    true,
    pub sequence_handle: TpmTransient,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSequenceUpdateCommand,
    TpmCc::SequenceUpdate,
    true,
    true,
    1,
    {
        pub buffer: Tpm2bMaxBuffer,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmSequenceUpdateResponse,
    TpmCc::SequenceUpdate,
    true,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSequenceCompleteCommand,
    TpmCc::SequenceComplete,
    true,
    true,
    1,
    {
        pub buffer: Tpm2bMaxBuffer,
        pub hierarchy: TpmRh,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSequenceCompleteResponse,
    TpmCc::SequenceComplete,
    true,
    true,
    {
        pub result: Tpm2bDigest,
        pub validation: TpmtTkHashcheck,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmEventSequenceCompleteCommand,
    TpmCc::EventSequenceComplete,
    true,
    true,
    2,
    {
        pub buffer: Tpm2bMaxBuffer,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmEventSequenceCompleteResponse,
    TpmCc::EventSequenceComplete,
    true,
    true,
    {
        pub results: TpmlDigestValues,
    }
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicySignedCommand,
    TpmCc::PolicySigned,
    false,
    true,
    2,
    {
        pub nonce_tpm: crate::data::Tpm2bNonce,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: crate::data::Tpm2bNonce,
        pub expiration: i32,
        pub auth: TpmtSignature,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicySignedResponse,
    TpmCc::PolicySigned,
    false,
    true,
    {
        pub timeout: Tpm2bTimeout,
        pub policy_ticket: TpmtTkAuth,
    }
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyTicketCommand,
    TpmCc::PolicyTicket,
    false,
    true,
    1,
    {
        pub timeout: Tpm2bTimeout,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: crate::data::Tpm2bNonce,
        pub auth_name: Tpm2bName,
        pub ticket: TpmtTkAuth,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyTicketResponse,
    TpmCc::PolicyTicket,
    false,
    true,
    {}
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    TpmPolicyLocalityCommand,
    TpmCc::PolicyLocality,
    false,
    true,
    1,
    {
        pub locality: TpmaLocality,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyLocalityResponse,
    TpmCc::PolicyLocality,
    false,
    true,
    {}
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPolicyCpHashCommand,
    TpmCc::PolicyCpHash,
    false,
    true,
    1,
    {
        pub cp_hash_a: Tpm2bDigest,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyCpHashResponse,
    TpmCc::PolicyCpHash,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyPhysicalPresenceCommand,
    TpmCc::PolicyPhysicalPresence,
    false,
    true,
    1,
    {}
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPolicyPhysicalPresenceResponse,
    TpmCc::PolicyPhysicalPresence,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHierarchyControlCommand,
    TpmCc::HierarchyControl,
    false,
    true,
    1,
    {
        pub enable: TpmRh,
        pub state: TpmiYesNo,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmHierarchyControlResponse,
    TpmCc::HierarchyControl,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmSetPrimaryPolicyCommand,
    TpmCc::SetPrimaryPolicy,
    false,
    true,
    1,
    {
        pub auth_policy: Tpm2bDigest,
        pub hash_alg: TpmAlgId,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmSetPrimaryPolicyResponse,
    TpmCc::SetPrimaryPolicy,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangePpsCommand,
    TpmCc::ChangePps,
    false,
    true,
    1,
    {}
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangePpsResponse,
    TpmCc::ChangePps,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangeEpsCommand,
    TpmCc::ChangeEps,
    false,
    true,
    1,
    {}
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmChangeEpsResponse,
    TpmCc::ChangeEps,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClearCommand,
    TpmCc::Clear,
    false,
    true,
    1,
    {}
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClearResponse,
    TpmCc::Clear,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmClearControlCommand,
    TpmCc::ClearControl,
    false,
    true,
    1,
    {
        pub disable: TpmiYesNo,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmClearControlResponse,
    TpmCc::ClearControl,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmHierarchyChangeAuthCommand,
    TpmCc::HierarchyChangeAuth,
    false,
    true,
    1,
    {
        pub new_auth: Tpm2bAuth,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmHierarchyChangeAuthResponse,
    TpmCc::HierarchyChangeAuth,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrExtendCommand,
    TpmCc::PcrExtend,
    false,
    true,
    1,
    {
        pub digests: TpmlDigestValues,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPcrExtendResponse,
    TpmCc::PcrExtend,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrAllocateCommand,
    TpmCc::PcrAllocate,
    false,
    true,
    1,
    {
        pub pcr_allocation: TpmlPcrSelection,
    }
);

tpm_response!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrAllocateResponse,
    TpmCc::PcrAllocate,
    false,
    true,
    {
        pub allocation_success: TpmiYesNo,
        pub max_pcr: u32,
        pub size_needed: u32,
        pub size_available: u32,
    }
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrSetAuthPolicyCommand,
    TpmCc::PcrSetAuthPolicy,
    false,
    true,
    1,
    {
        pub auth_policy: Tpm2bDigest,
        pub hash_alg: TpmAlgId,
        pub pcr_num: TpmRh,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPcrSetAuthPolicyResponse,
    TpmCc::PcrSetAuthPolicy,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, PartialEq, Eq, Clone)]
    TpmPcrSetAuthValueCommand,
    TpmCc::PcrSetAuthValue,
    false,
    true,
    1,
    {
        pub auth: Tpm2bDigest,
    }
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPcrSetAuthValueResponse,
    TpmCc::PcrSetAuthValue,
    false,
    true,
    {}
);

tpm_struct!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPcrResetCommand,
    TpmCc::PcrReset,
    false,
    true,
    1,
    {}
);

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    TpmPcrResetResponse,
    TpmCc::PcrReset,
    false,
    true,
    {}
);

tpm_dispatch! {
    (TpmNvUndefineSpaceSpecialCommand, TpmNvUndefineSpaceSpecialResponse, NvUndefineSpaceSpecial),
    (TpmEvictControlCommand, TpmEvictControlResponse, EvictControl),
    (TpmHierarchyControlCommand, TpmHierarchyControlResponse, HierarchyControl),
    (TpmNvUndefineSpaceCommand, TpmNvUndefineSpaceResponse, NvUndefineSpace),
    (TpmChangeEpsCommand, TpmChangeEpsResponse, ChangeEps),
    (TpmChangePpsCommand, TpmChangePpsResponse, ChangePps),
    (TpmClearCommand, TpmClearResponse, Clear),
    (TpmClearControlCommand, TpmClearControlResponse, ClearControl),
    (TpmHierarchyChangeAuthCommand, TpmHierarchyChangeAuthResponse, HierarchyChangeAuth),
    (TpmNvDefineSpaceCommand, TpmNvDefineSpaceResponse, NvDefineSpace),
    (TpmPcrAllocateCommand, TpmPcrAllocateResponse, PcrAllocate),
    (TpmPcrSetAuthPolicyCommand, TpmPcrSetAuthPolicyResponse, PcrSetAuthPolicy),
    (TpmSetPrimaryPolicyCommand, TpmSetPrimaryPolicyResponse, SetPrimaryPolicy),
    (TpmCreatePrimaryCommand, TpmCreatePrimaryResponse, CreatePrimary),
    (TpmNvGlobalWriteLockCommand, TpmNvGlobalWriteLockResponse, NvGlobalWriteLock),
    (TpmGetCommandAuditDigestCommand, TpmGetCommandAuditDigestResponse, GetCommandAuditDigest),
    (TpmNvIncrementCommand, TpmNvIncrementResponse, NvIncrement),
    (TpmNvSetBitsCommand, TpmNvSetBitsResponse, NvSetBits),
    (TpmNvExtendCommand, TpmNvExtendResponse, NvExtend),
    (TpmNvWriteCommand, TpmNvWriteResponse, NvWrite),
    (TpmNvWriteLockCommand, TpmNvWriteLockResponse, NvWriteLock),
    (TpmDictionaryAttackLockResetCommand, TpmDictionaryAttackLockResetResponse, DictionaryAttackLockReset),
    (TpmNvChangeAuthCommand, TpmNvChangeAuthResponse, NvChangeAuth),
    (TpmPcrEventCommand, TpmPcrEventResponse, PcrEvent),
    (TpmPcrResetCommand, TpmPcrResetResponse, PcrReset),
    (TpmSequenceCompleteCommand, TpmSequenceCompleteResponse, SequenceComplete),
    (TpmIncrementalSelfTestCommand, TpmIncrementalSelfTestResponse, IncrementalSelfTest),
    (TpmSelfTestCommand, TpmSelfTestResponse, SelfTest),
    (TpmStartupCommand, TpmStartupResponse, Startup),
    (TpmShutdownCommand, TpmShutdownResponse, Shutdown),
    (TpmStirRandomCommand, TpmStirRandomResponse, StirRandom),
    (TpmActivateCredentialCommand, TpmActivateCredentialResponse, ActivateCredential),
    (TpmCertifyCommand, TpmCertifyResponse, Certify),
    (TpmCertifyCreationCommand, TpmCertifyCreationResponse, CertifyCreation),
    (TpmDuplicateCommand, TpmDuplicateResponse, Duplicate),
    (TpmGetTimeCommand, TpmGetTimeResponse, GetTime),
    (TpmGetSessionAuditDigestCommand, TpmGetSessionAuditDigestResponse, GetSessionAuditDigest),
    (TpmNvReadCommand, TpmNvReadResponse, NvRead),
    (TpmNvReadLockCommand, TpmNvReadLockResponse, NvReadLock),
    (TpmObjectChangeAuthCommand, TpmObjectChangeAuthResponse, ObjectChangeAuth),
    (TpmPolicySecretCommand, TpmPolicySecretResponse, PolicySecret),
    (TpmRewrapCommand, TpmRewrapResponse, Rewrap),
    (TpmCreateCommand, TpmCreateResponse, Create),
    (TpmEcdhZGenCommand, TpmEcdhZGenResponse, EcdhZGen),
    (TpmImportCommand, TpmImportResponse, Import),
    (TpmLoadCommand, TpmLoadResponse, Load),
    (TpmQuoteCommand, TpmQuoteResponse, Quote),
    (TpmRsaDecryptCommand, TpmRsaDecryptResponse, RsaDecrypt),
    (TpmSequenceUpdateCommand, TpmSequenceUpdateResponse, SequenceUpdate),
    (TpmSignCommand, TpmSignResponse, Sign),
    (TpmUnsealCommand, TpmUnsealResponse, Unseal),
    (TpmPolicySignedCommand, TpmPolicySignedResponse, PolicySigned),
    (TpmContextLoadCommand, TpmContextLoadResponse, ContextLoad),
    (TpmContextSaveCommand, TpmContextSaveResponse, ContextSave),
    (TpmEcdhKeyGenCommand, TpmEcdhKeyGenResponse, EcdhKeyGen),
    (TpmFlushContextCommand, TpmFlushContextResponse, FlushContext),
    (TpmLoadExternalCommand, TpmLoadExternalResponse, LoadExternal),
    (TpmMakeCredentialCommand, TpmMakeCredentialResponse, MakeCredential),
    (TpmNvReadPublicCommand, TpmNvReadPublicResponse, NvReadPublic),
    (TpmPolicyAuthValueCommand, TpmPolicyAuthValueResponse, PolicyAuthValue),
    (TpmPolicyCommandCodeCommand, TpmPolicyCommandCodeResponse, PolicyCommandCode),
    (TpmPolicyCpHashCommand, TpmPolicyCpHashResponse, PolicyCpHash),
    (TpmPolicyLocalityCommand, TpmPolicyLocalityResponse, PolicyLocality),
    (TpmPolicyOrCommand, TpmPolicyOrResponse, PolicyOr),
    (TpmPolicyTicketCommand, TpmPolicyTicketResponse, PolicyTicket),
    (TpmReadPublicCommand, TpmReadPublicResponse, ReadPublic),
    (TpmRsaEncryptCommand, TpmRsaEncryptResponse, RsaEncrypt),
    (TpmStartAuthSessionCommand, TpmStartAuthSessionResponse, StartAuthSession),
    (TpmVerifySignatureCommand, TpmVerifySignatureResponse, VerifySignature),
    (TpmEccParametersCommand, TpmEccParametersResponse, EccParameters),
    (TpmGetCapabilityCommand, TpmGetCapabilityResponse, GetCapability),
    (TpmGetRandomCommand, TpmGetRandomResponse, GetRandom),
    (TpmGetTestResultCommand, TpmGetTestResultResponse, GetTestResult),
    (TpmHashCommand, TpmHashResponse, Hash),
    (TpmPcrReadCommand, TpmPcrReadResponse, PcrRead),
    (TpmPolicyPcrCommand, TpmPolicyPcrResponse, PolicyPcr),
    (TpmPolicyRestartCommand, TpmPolicyRestartResponse, PolicyRestart),
    (TpmPcrExtendCommand, TpmPcrExtendResponse, PcrExtend),
    (TpmPcrSetAuthValueCommand, TpmPcrSetAuthValueResponse, PcrSetAuthValue),
    (TpmNvCertifyCommand, TpmNvCertifyResponse, NvCertify),
    (TpmEventSequenceCompleteCommand, TpmEventSequenceCompleteResponse, EventSequenceComplete),
    (TpmHashSequenceStartCommand, TpmHashSequenceStartResponse, HashSequenceStart),
    (TpmPolicyPhysicalPresenceCommand, TpmPolicyPhysicalPresenceResponse, PolicyPhysicalPresence),
    (TpmPolicyGetDigestCommand, TpmPolicyGetDigestResponse, PolicyGetDigest),
    (TpmPolicyPasswordCommand, TpmPolicyPasswordResponse, PolicyPassword),
    (TpmEncryptDecrypt2Command, TpmEncryptDecrypt2Response, EncryptDecrypt2),
    (TpmVendorTcgTestCommand, TpmVendorTcgTestResponse, VendorTcgTest),
}
