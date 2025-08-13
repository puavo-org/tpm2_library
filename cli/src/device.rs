// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::TpmError;
use std::{
    fs::{self, File, OpenOptions},
    io::{Error as IoError, ErrorKind, Read, Write as IoWrite},
    os::unix::fs::FileTypeExt,
    path::Path,
};
use tpm2_protocol::{
    self,
    data::{self, TpmSt, TpmuCapabilities},
    message::{TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmReadPublicCommand},
    TpmWriter, TPM_MAX_COMMAND_SIZE,
};
use tracing::{debug, trace};

pub const TPM_CAP_PROPERTY_MAX: u32 = 128;

pub struct TpmDevice(File);

impl TpmDevice {
    /// Opens a TPM device node.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::File` if the path does not exist, is not a character
    /// device, or cannot be opened for reading and writing.
    pub fn open(path: &str) -> Result<TpmDevice, TpmError> {
        let path_obj = Path::new(path);
        let metadata = fs::metadata(path_obj).map_err(|e| TpmError::File(path.to_string(), e))?;
        if !metadata.file_type().is_char_device() {
            return Err(TpmError::File(
                path.to_string(),
                IoError::new(ErrorKind::InvalidInput, "not a device node"),
            ));
        }
        let canonical_path =
            std::fs::canonicalize(path_obj).map_err(|e| TpmError::File(path.to_string(), e))?;
        debug!(device_path = %canonical_path.display(), "opening");
        Ok(TpmDevice(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(canonical_path)
                .map_err(|e| TpmError::File(path.to_string(), e))?,
        ))
    }

    /// Executes a TPM command.
    ///
    /// Builds a command, sends it to the TPM, and parses the response.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if building the command, communicating with the device,
    /// or parsing the response fails. A `TpmError::TpmRc` variant is returned
    /// for TPM-specific operational errors.
    pub fn execute<C>(
        &mut self,
        command: &C,
        handles: Option<&[u32]>,
        sessions: &[tpm2_protocol::data::TpmsAuthCommand],
    ) -> Result<
        (
            tpm2_protocol::message::TpmResponseBody,
            tpm2_protocol::message::TpmAuthResponses,
        ),
        TpmError,
    >
    where
        C: for<'a> tpm2_protocol::message::TpmHeader<'a>,
    {
        let mut command_buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut command_buf);
            let tag = if sessions.is_empty() {
                TpmSt::NoSessions
            } else {
                TpmSt::Sessions
            };
            tpm2_protocol::message::tpm_build_command(
                command,
                tag,
                handles,
                sessions,
                &mut writer,
            )?;
            writer.len()
        };
        let final_command = &command_buf[..len];

        trace!(command = %hex::encode(final_command), "Command");
        std::io::Write::write_all(&mut self.0, final_command)?;
        self.0.flush()?;
        let mut resp_buf = Vec::new();
        std::io::Read::read_to_end(&mut self.0, &mut resp_buf)?;
        trace!(response = %hex::encode(&resp_buf), "Response");
        match tpm2_protocol::message::tpm_parse_response(C::COMMAND, &resp_buf)? {
            Ok((response, auth)) => Ok((response, auth)),
            Err(rc) => Err(TpmError::TpmRc(rc)),
        }
    }

    /// Retrieves the names for a list of handles.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the underlying `execute` call fails.
    pub fn get_handle_names(&mut self, handles: &[u32]) -> Result<Vec<Vec<u8>>, TpmError> {
        handles
            .iter()
            .map(|&handle| {
                let cmd = TpmReadPublicCommand {};
                let (resp, _) = self.execute(&cmd, Some(&[handle]), &[])?;
                let read_public_resp = resp
                    .ReadPublic()
                    .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
                Ok(read_public_resp.name.to_vec())
            })
            .collect()
    }

    /// Fetches and returns all capabilities of a certain type from the TPM.
    ///
    /// Handles the paging mechanism for capabilities that return more than one
    /// batch of data.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the underlying `execute` call fails or if the
    /// TPM returns an unexpected response type.
    pub fn get_capability(
        &mut self,
        cap: data::TpmCap,
        mut property: u32,
        count: u32,
    ) -> Result<Vec<data::TpmsCapabilityData>, TpmError> {
        let mut all_caps = Vec::new();
        loop {
            let cmd = TpmGetCapabilityCommand {
                cap,
                property,
                property_count: count,
            };

            let (resp, _) = self.execute(&cmd, None, &[])?;
            let TpmGetCapabilityResponse {
                more_data,
                capability_data,
            } = resp
                .GetCapability()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

            let next_prop = if more_data.into() {
                match &capability_data.data {
                    TpmuCapabilities::Algs(algs) => algs.last().map(|p| p.alg as u32 + 1),
                    TpmuCapabilities::Handles(handles) => handles.last().map(|&h| h + 1),
                    TpmuCapabilities::Pcrs(_) => None,
                }
            } else {
                None
            };

            all_caps.push(capability_data);

            if let Some(p) = next_prop {
                property = p;
            } else {
                break;
            }
        }
        Ok(all_caps)
    }
}

impl Read for TpmDevice {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        self.0.read(buf)
    }
}

impl IoWrite for TpmDevice {
    fn write(&mut self, buf: &[u8]) -> Result<usize, IoError> {
        std::io::Write::write(&mut self.0, buf)
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.0.flush()
    }
}
