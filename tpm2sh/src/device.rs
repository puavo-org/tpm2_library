// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli, pretty_printer::PrettyTrace, TpmError};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, trace, warn};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    path::Path,
    sync::mpsc,
    thread,
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
        debug!(target: "cli::device", "opening device_path = {path}");
        Ok(TpmDevice { file })
    }

    /// Sends a command to the TPM and waits for the response.
    ///
    /// Displays a spinner on stderr if the operation takes longer than one second.
    ///
    /// # Errors
    ///
    /// This function will return an error if building the command fails, I/O
    /// with the device fails, or the TPM itself returns an error.
    pub fn execute<C>(
        &mut self,
        command: &C,
        sessions: &[tpm2_protocol::data::TpmsAuthCommand],
        log_format: cli::LogFormat,
    ) -> Result<(TpmResponseBody, tpm2_protocol::message::TpmAuthResponses), TpmError>
    where
        C: tpm2_protocol::message::TpmHeaderCommand + PrettyTrace,
    {
        let mut command_buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut command_buf);
            let tag = if sessions.is_empty() {
                TpmSt::NoSessions
            } else {
                TpmSt::Sessions
            };
            tpm2_protocol::message::tpm_build_command(command, tag, sessions, &mut writer)?;
            writer.len()
        };
        let command_bytes = &command_buf[..len];
        let style = ProgressStyle::with_template("{spinner:.cyan.bold} {msg}")?
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);

        let (tx, rx) = mpsc::channel::<()>();
        let spinner_thread = if std::io::stderr().is_terminal() {
            let handle = thread::spawn(move || {
                if let Err(mpsc::RecvTimeoutError::Timeout) =
                    rx.recv_timeout(Duration::from_secs(1))
                {
                    let pb = ProgressBar::new_spinner();
                    pb.enable_steady_tick(Duration::from_millis(100));
                    pb.set_style(style);
                    pb.set_message("Waiting for TPM...");

                    let _ = rx.recv();
                    pb.finish_with_message("✔ TPM operation complete.");
                }
            });
            Some(handle)
        } else {
            None
        };

        match log_format {
            cli::LogFormat::Pretty => {
                trace!(target: "cli::device", "{}", C::COMMAND);
                command.pretty_trace("", 1);
            }
            cli::LogFormat::Plain => {
                trace!(target: "cli::device", "Command: {}", hex::encode(command_bytes));
            }
        }
        self.file.write_all(command_bytes)?;
        self.file.flush()?;

        let mut header = [0u8; 10];
        self.file.read_exact(&mut header)?;

        let Ok(size_bytes): Result<[u8; 4], _> = header[2..6].try_into() else {
            unreachable!();
        };
        let size = u32::from_be_bytes(size_bytes) as usize;

        if size < header.len() || size > TPM_MAX_COMMAND_SIZE {
            drop(tx);
            if let Some(handle) = spinner_thread {
                let _ = handle.join();
            }
            return Err(TpmError::Parse(format!(
                "Invalid response size in header: {size}"
            )));
        }

        let mut resp_buf = header.to_vec();
        resp_buf.resize(size, 0);
        self.file.read_exact(&mut resp_buf[header.len()..])?;

        drop(tx);
        if let Some(handle) = spinner_thread {
            let _ = handle.join();
        }

        let result = tpm2_protocol::message::tpm_parse_response(C::COMMAND, &resp_buf)?;

        match &result {
            Ok((rc, response_body, _)) => match log_format {
                cli::LogFormat::Pretty => {
                    trace!(target: "cli::device", "Response (rc={rc})");
                    response_body.pretty_trace("", 1);
                }
                cli::LogFormat::Plain => {
                    trace!(target: "cli::device", "Response: {}", hex::encode(&resp_buf));
                }
            },
            Err((rc, _)) => {
                trace!(target: "cli::device", "Error Response (rc={rc})");
                trace!(target: "cli::device", "Response: {}", hex::encode(&resp_buf));
            }
        }

        match result {
            Ok((rc, response, auth)) => {
                if rc.is_warning() {
                    warn!(target: "cli::device", "TPM command completed with a warning: rc = {rc}");
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
    pub fn get_handle_names(
        &mut self,
        handles: &[u32],
        log_format: cli::LogFormat,
    ) -> Result<Vec<Vec<u8>>, TpmError> {
        handles
            .iter()
            .map(|&handle| {
                let cmd = TpmReadPublicCommand {
                    object_handle: handle.into(),
                };
                let (resp, _) = self.execute(&cmd, &[], log_format)?;
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
        log_format: cli::LogFormat,
    ) -> Result<Vec<data::TpmsCapabilityData>, TpmError> {
        let mut all_caps = Vec::new();
        loop {
            let cmd = TpmGetCapabilityCommand {
                cap,
                property,
                property_count: count,
            };

            let (resp, _) = self.execute(&cmd, &[], log_format)?;
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

    /// Retrieves all algorithms supported by the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the `get_capability` call to the TPM device fails.
    pub fn get_all_algorithms(
        &mut self,
        log_format: cli::LogFormat,
    ) -> Result<HashSet<data::TpmAlgId>, TpmError> {
        let cap_data_vec =
            self.get_capability(data::TpmCap::Algs, 0, TPM_CAP_PROPERTY_MAX, log_format)?;
        let algs: HashSet<data::TpmAlgId> = cap_data_vec
            .into_iter()
            .flat_map(|cap_data| {
                if let TpmuCapabilities::Algs(p) = cap_data.data {
                    p.iter().map(|prop| prop.alg).collect::<Vec<_>>()
                } else {
                    Vec::new()
                }
            })
            .collect();
        Ok(algs)
    }

    /// Retrieves all handles of a specific type from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the `get_capability` call to the TPM device fails.
    pub fn get_all_handles(
        &mut self,
        handle_type: data::TpmRh,
        log_format: cli::LogFormat,
    ) -> Result<Vec<u32>, TpmError> {
        let cap_data_vec = self.get_capability(
            data::TpmCap::Handles,
            handle_type as u32,
            TPM_CAP_PROPERTY_MAX,
            log_format,
        )?;
        let handles: Vec<u32> = cap_data_vec
            .into_iter()
            .flat_map(|cap_data| {
                if let TpmuCapabilities::Handles(handles) = cap_data.data {
                    handles.iter().copied().collect()
                } else {
                    Vec::new()
                }
            })
            .collect();
        Ok(handles)
    }
}
