// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    data::{TpmRc, TpmSt, TpmsAuthCommand, TpmsAuthResponse},
    message::{TpmHeader, TpmHeaderCommand, TPM_HEADER_SIZE},
    TpmBuild, TpmErrorKind, TpmResult, TpmSized,
};
use core::mem::size_of;

/// Builds a TPM command into a writer and returns the total bytes written.
///
/// # Errors
///
/// * `TpmErrorKind::ValueTooLarge` if the command has unknown state
pub fn tpm_build_command<C>(
    command: &C,
    tag: TpmSt,
    sessions: &[TpmsAuthCommand],
    writer: &mut crate::TpmWriter,
) -> TpmResult<()>
where
    C: TpmHeaderCommand,
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

    let handle_area_size = C::HANDLES * size_of::<u32>();
    let param_area_size = command.len() - handle_area_size;
    let auth_area_size = if tag == TpmSt::Sessions {
        let sessions_len: usize = sessions.iter().map(TpmSized::len).sum();
        size_of::<u32>() + sessions_len
    } else {
        0
    };

    let total_body_len = handle_area_size + auth_area_size + param_area_size;
    let command_size =
        u32::try_from(TPM_HEADER_SIZE + total_body_len).map_err(|_| TpmErrorKind::ValueTooLarge)?;

    (tag as u16).build(writer)?;
    command_size.build(writer)?;
    (C::COMMAND as u32).build(writer)?;

    command.build_handles(writer)?;

    if tag == TpmSt::Sessions {
        let sessions_len_u32 = u32::try_from(auth_area_size - size_of::<u32>())
            .map_err(|_| TpmErrorKind::ValueTooLarge)?;
        sessions_len_u32.build(writer)?;
        for s in sessions {
            s.build(writer)?;
        }
    }

    command.build_parameters(writer)
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
    R: TpmHeader,
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
