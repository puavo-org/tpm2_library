// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    data::{
        Tpm2b, Tpm2bAuth, Tpm2bCreationData, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret,
        Tpm2bMaxBuffer, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bTimeout,
        TpmAlgId, TpmCap, TpmCc, TpmRc, TpmRh, TpmSe, TpmSt, TpmiYesNo, TpmlDigest,
        TpmlDigestValues, TpmlPcrSelection, TpmsAuthCommand, TpmsAuthResponse, TpmsCapabilityData,
        TpmsContext, TpmtSymDef, TpmtSymDefObject, TpmtTkAuth, TpmtTkCreation, TpmtTkHashcheck,
    },
    tpm_dispatch, tpm_response, tpm_struct, TpmBuild, TpmErrorKind, TpmList, TpmParse,
    TpmPersistent, TpmResult, TpmSession, TpmSized, TpmTransient,
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

pub type TpmResponse = Result<(TpmResponseBody, TpmAuthResponses), TpmRc>;

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
    let tag = if rc.value() == 0 && R::WITH_SESSIONS && !sessions.is_empty() {
        TpmSt::Sessions
    } else {
        TpmSt::NoSessions
    };

    if rc.value() != 0 {
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
pub fn tpm_parse_response(cc: TpmCc, buf: &[u8]) -> TpmResult<TpmResponse> {
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
    let tag = TpmSt::try_from(tag_raw).map_err(|()| TpmErrorKind::InvalidDiscriminant {
        type_name: "TpmSt",
        value: u64::from(tag_raw),
    })?;

    if rc.value() != 0 {
        if tag != TpmSt::NoSessions {
            return Err(TpmErrorKind::InvalidTag {
                type_name: "TpmSt",
                expected: TpmSt::NoSessions as u16,
                got: tag_raw,
            });
        }
        if size != u32::try_from(TPM_HEADER_SIZE)? {
            return Err(TpmErrorKind::Boundary);
        }
        return Ok(Err(rc));
    }

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

    Ok(Ok((body, auth_responses)))
}

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
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPolicyGetDigestResponse,
    TpmCc::PolicyGetDigest,
    false,
    true,
    0,
    {
        pub policy_digest: Tpm2bDigest,
    }
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
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPolicyPcrResponse,
    TpmCc::PolicyPcr,
    false,
    true,
    0,
    {
        pub pcr_digest: Tpm2bDigest,
        pub pcrs: TpmlPcrSelection,
    }
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

tpm_response!(
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    TpmPolicySecretResponse,
    TpmCc::PolicySecret,
    false,
    true,
    {
        pub timeout: Tpm2bTimeout,
        pub policy_ticket: TpmtTkAuth,
    }
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

tpm_dispatch! {
    (TpmEvictControlCommand, TpmEvictControlResponse, EvictControl),
    (TpmCreatePrimaryCommand, TpmCreatePrimaryResponse, CreatePrimary),
    (TpmDictionaryAttackLockResetCommand, TpmDictionaryAttackLockResetResponse, DictionaryAttackLockReset),
    (TpmPcrEventCommand, TpmPcrEventResponse, PcrEvent),
    (TpmObjectChangeAuthCommand, TpmObjectChangeAuthResponse, ObjectChangeAuth),
    (TpmPolicySecretCommand, TpmPolicySecretResponse, PolicySecret),
    (TpmCreateCommand, TpmCreateResponse, Create),
    (TpmImportCommand, TpmImportResponse, Import),
    (TpmLoadCommand, TpmLoadResponse, Load),
    (TpmUnsealCommand, TpmUnsealResponse, Unseal),
    (TpmContextLoadCommand, TpmContextLoadResponse, ContextLoad),
    (TpmContextSaveCommand, TpmContextSaveResponse, ContextSave),
    (TpmFlushContextCommand, TpmFlushContextResponse, FlushContext),
    (TpmPolicyAuthValueCommand, TpmPolicyAuthValueResponse, PolicyAuthValue),
    (TpmPolicyCommandCodeCommand, TpmPolicyCommandCodeResponse, PolicyCommandCode),
    (TpmPolicyOrCommand, TpmPolicyOrResponse, PolicyOr),
    (TpmReadPublicCommand, TpmReadPublicResponse, ReadPublic),
    (TpmStartAuthSessionCommand, TpmStartAuthSessionResponse, StartAuthSession),
    (TpmGetCapabilityCommand, TpmGetCapabilityResponse, GetCapability),
    (TpmHashCommand, TpmHashResponse, Hash),
    (TpmPcrReadCommand, TpmPcrReadResponse, PcrRead),
    (TpmPolicyPcrCommand, TpmPolicyPcrResponse, PolicyPcr),
    (TpmPolicyRestartCommand, TpmPolicyRestartResponse, PolicyRestart),
    (TpmPolicyGetDigestCommand, TpmPolicyGetDigestResponse, PolicyGetDigest),
    (TpmPolicyPasswordCommand, TpmPolicyPasswordResponse, PolicyPassword),
    (TpmVendorTcgTestCommand, TpmVendorTcgTestResponse, VendorTcgTest),
}
