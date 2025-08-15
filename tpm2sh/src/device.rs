// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::TpmError;
use indicatif::{ProgressBar, ProgressStyle};
use std::{
    fs::{File, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    path::Path,
    time::Duration,
};
use tpm2_protocol::{
    self,
    data::{self, TpmSt, TpmuCapabilities},
    message::{
        TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmReadPublicCommand, TpmResponseBody,
    },
    TpmWriter, TPM_MAX_COMMAND_SIZE,
};
use tracing::{trace, warn};

pub const TPM_CAP_PROPERTY_MAX: u32 = 128;

pub struct TpmDevice {
    file: File,
}

impl TpmDevice {
    /// Opens a TPM device for communication.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::File` if the path cannot be opened.
    pub fn new(path: &str) -> Result<TpmDevice, TpmError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(Path::new(path))
            .map_err(|e| {
                TpmError::File(
                    path.to_string(),
                    io::Error::new(e.kind(), "could not open device node"),
                )
            })?;
        tracing::debug!(device_path = %path, "opening");
        Ok(TpmDevice { file })
    }

    /// Sends a command to the TPM and waits for the response.
    ///
    /// Displays a spinner on stderr if the operation is long-running.
    ///
    /// # Errors
    ///
    /// This function will return an error if building the command fails, I/O
    /// with the device fails, or the TPM itself returns an error.
    pub fn execute<C>(
        &mut self,
        command: &C,
        handles: Option<&[u32]>,
        sessions: &[tpm2_protocol::data::TpmsAuthCommand],
    ) -> Result<(TpmResponseBody, tpm2_protocol::message::TpmAuthResponses), TpmError>
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
        let command_bytes = &command_buf[..len];

        let maybe_pb = if std::io::stderr().is_terminal() {
            let pb = ProgressBar::new_spinner();
            pb.enable_steady_tick(Duration::from_millis(100));
            pb.set_style(
                ProgressStyle::with_template("{spinner:.cyan.bold} {msg}")?
                    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
            );
            pb.set_message("Waiting for TPM...");
            Some(pb)
        } else {
            None
        };

        trace!(command = %hex::encode(command_bytes), "Command");
        self.file.write_all(command_bytes)?;
        self.file.flush()?;

        let mut header = [0u8; 10];
        self.file.read_exact(&mut header)?;

        let Ok(size_bytes): Result<[u8; 4], _> = header[2..6].try_into() else {
            unreachable!();
        };
        let size = u32::from_be_bytes(size_bytes) as usize;

        if size < header.len() || size > TPM_MAX_COMMAND_SIZE {
            if let Some(pb) = maybe_pb {
                pb.abandon_with_message("✖ Invalid response size in TPM header.");
            }
            return Err(TpmError::Parse(format!(
                "Invalid response size in header: {size}"
            )));
        }

        let mut resp_buf = header.to_vec();
        resp_buf.resize(size, 0);
        self.file.read_exact(&mut resp_buf[header.len()..])?;

        if let Some(pb) = maybe_pb {
            pb.finish_with_message("✔ TPM operation complete.");
        }

        trace!(response = %hex::encode(&resp_buf), "Response");

        match tpm2_protocol::message::tpm_parse_response(C::COMMAND, &resp_buf)? {
            Ok((rc, response, auth)) => {
                if rc.is_warning() {
                    warn!(rc = %rc, "TPM command completed with a warning");
                }
                Ok((response, auth))
            }
            Err((rc, _)) => Err(TpmError::TpmRc(rc)),
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
    /// # Errors
    ///
    /// This function will return an error if the underlying `execute` call fails
    /// or if the TPM returns a response of an unexpected type.
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
