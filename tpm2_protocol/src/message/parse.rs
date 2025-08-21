// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{
    TpmAuthCommands, TpmAuthResponses, TpmCommandBody, TpmHandles, TpmResponseBody,
    PARSE_COMMAND_MAP, PARSE_RESPONSE_MAP, TPM_HEADER_SIZE,
};
use crate::{
    data::{TpmCc, TpmRc, TpmSt, TpmsAuthCommand, TpmsAuthResponse},
    TpmErrorKind, TpmNotDiscriminant, TpmParse, TpmResult, TPM_MAX_COMMAND_SIZE,
};
use core::{convert::TryFrom, mem::size_of};

/// The result of parsing a TPM response, containing either the successfully parsed
/// body and auth areas (with a success or warning code) or a fatal error code.
pub type TpmParseResult<'a> = Result<(TpmRc, TpmResponseBody, TpmAuthResponses), (TpmRc, &'a [u8])>;

/// Parses a command from a TPM command buffer.
///
/// # Errors
///
/// * `TpmErrorKind::Boundary` if the buffer is too small
/// * `TpmErrorKind::NotDiscriminant` if the buffer contains an unsupported command code or unexpected byte
/// * `TpmErrorKind::TrailingData` if the command has after spurious data left
pub fn tpm_parse_command(buf: &[u8]) -> TpmResult<(TpmHandles, TpmCommandBody, TpmAuthCommands)> {
    if buf.len() < TPM_HEADER_SIZE {
        return Err(TpmErrorKind::Boundary);
    }
    let command_len = buf.len();

    let (tag_raw, buf) = u16::parse(buf)?;
    let tag = TpmSt::try_from(tag_raw).map_err(|()| {
        TpmErrorKind::NotDiscriminant("TpmSt", TpmNotDiscriminant::Unsigned(u64::from(tag_raw)))
    })?;
    let (size, buf) = u32::parse(buf)?;
    let (cc_raw, body_buf) = u32::parse(buf)?;

    if command_len != size as usize {
        return Err(TpmErrorKind::Boundary);
    }

    let cc = TpmCc::try_from(cc_raw).map_err(|()| {
        TpmErrorKind::NotDiscriminant("TpmCc", TpmNotDiscriminant::Unsigned(u64::from(cc_raw)))
    })?;
    let dispatch = PARSE_COMMAND_MAP
        .binary_search_by_key(&cc, |d| d.0)
        .map(|index| &PARSE_COMMAND_MAP[index])
        .map_err(|_| {
            TpmErrorKind::NotDiscriminant("TpmCc", TpmNotDiscriminant::Unsigned(u64::from(cc_raw)))
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

    let handle_area_size = dispatch.3 * size_of::<u32>();
    if body_buf.len() < handle_area_size {
        return Err(TpmErrorKind::Boundary);
    }
    let (handle_area, after_handles) = body_buf.split_at(handle_area_size);

    let mut sessions = TpmAuthCommands::new();
    let param_area = if tag == TpmSt::Sessions {
        let (auth_area_size, buf_after_auth_size) = u32::parse(after_handles)?;
        let auth_area_size = auth_area_size as usize;
        if buf_after_auth_size.len() < auth_area_size {
            return Err(TpmErrorKind::Boundary);
        }
        let (mut auth_area, param_area) = buf_after_auth_size.split_at(auth_area_size);
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
        param_area
    } else {
        after_handles
    };

    let mut temp_body_buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let full_body_len = handle_area.len() + param_area.len();
    if full_body_len > temp_body_buf.len() {
        return Err(TpmErrorKind::ValueTooLarge);
    }
    let full_body_for_parser = &mut temp_body_buf[..full_body_len];
    full_body_for_parser[..handle_area.len()].copy_from_slice(handle_area);
    full_body_for_parser[handle_area.len()..].copy_from_slice(param_area);

    let (command_data, remainder) = (dispatch.4)(full_body_for_parser)?;

    if !remainder.is_empty() {
        return Err(TpmErrorKind::TrailingData);
    }

    let mut handles = TpmHandles::new();
    let mut temp_handle_cursor = handle_area;
    while !temp_handle_cursor.is_empty() {
        let (handle, rest) = u32::parse(temp_handle_cursor)?;
        handles.try_push(handle)?;
        temp_handle_cursor = rest;
    }

    Ok((handles, command_data, sessions))
}

/// Parses a response from a TPM response buffer.
///
/// # Errors
///
/// * `TpmErrorKind::Boundary` if the buffer is too small
/// * `TpmErrorKind::InvalidTag` if the tag in the buffer does not match expected
/// * `TpmErrorKind::NotDiscriminant` if the buffer contains an unsupported command code
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

    let tag = TpmSt::try_from(tag_raw).map_err(|()| {
        TpmErrorKind::NotDiscriminant("TpmSt", TpmNotDiscriminant::Unsigned(u64::from(tag_raw)))
    })?;

    let dispatch = PARSE_RESPONSE_MAP
        .binary_search_by_key(&cc, |d| d.0)
        .map(|index| &PARSE_RESPONSE_MAP[index])
        .map_err(|_| {
            TpmErrorKind::NotDiscriminant(
                "TpmCc",
                TpmNotDiscriminant::Unsigned(u64::from(cc as u32)),
            )
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
