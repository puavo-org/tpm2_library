// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::TpmError;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write as IoWrite},
    path::Path,
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tpm2_protocol::{
    self,
    data::{self, TpmCc, TpmSt, TpmuCapabilities},
    message::{
        TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmReadPublicCommand, TpmResponseBody,
    },
    TpmWriter, TPM_MAX_COMMAND_SIZE,
};
use tracing::{debug, trace, warn};

pub const TPM_CAP_PROPERTY_MAX: u32 = 128;

type TpmExecuteResult =
    Result<(TpmResponseBody, tpm2_protocol::message::TpmAuthResponses), TpmError>;
type TpmResponseSender = Sender<TpmExecuteResult>;

struct TpmCommandMsg {
    command_bytes: Vec<u8>,
    command_code: TpmCc,
    response_tx: TpmResponseSender,
}

pub struct TpmDevice {
    command_tx: Option<Sender<TpmCommandMsg>>,
    worker_handle: Option<JoinHandle<()>>,
}

/// Executes a command by performing a blocking, protocol-aware sized read/write.
fn execute_blocking(
    file: &mut File,
    command_code: TpmCc,
    command_bytes: &[u8],
) -> TpmExecuteResult {
    trace!(command = %hex::encode(command_bytes), "Command");
    file.write_all(command_bytes)?;
    file.flush()?;

    let mut header = [0u8; 10];
    file.read_exact(&mut header)?;

    let size = u32::from_be_bytes(header[2..6].try_into().unwrap());
    if (size as usize) < header.len() {
        return Err(TpmError::Parse(
            "Invalid response size in header".to_string(),
        ));
    }

    let mut resp_buf = header.to_vec();
    resp_buf.resize(size as usize, 0);
    file.read_exact(&mut resp_buf[header.len()..])?;

    trace!(response = %hex::encode(&resp_buf), "Response");

    match tpm2_protocol::message::tpm_parse_response(command_code, &resp_buf)? {
        Ok((rc, response, auth)) => {
            if rc.is_warning() {
                warn!(rc = %rc, "TPM command completed with a warning");
            }
            Ok((response, auth))
        }
        Err((rc, _)) => Err(TpmError::TpmRc(rc)),
    }
}

impl TpmDevice {
    /// Opens a TPM device and spawns a worker thread to handle communication.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::File` if the path cannot be opened.
    pub fn new(path: &str) -> Result<TpmDevice, TpmError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(Path::new(path))
            .map_err(|e| {
                TpmError::File(
                    path.to_string(),
                    io::Error::new(e.kind(), "could not open device node"),
                )
            })?;
        debug!(device_path = %path, "opening");

        let (command_tx, command_rx): (Sender<TpmCommandMsg>, Receiver<TpmCommandMsg>) =
            mpsc::channel();

        let worker_handle = Some(thread::spawn(move || {
            for msg in command_rx {
                let result = execute_blocking(&mut file, msg.command_code, &msg.command_bytes);
                let _ = msg.response_tx.send(result);
            }
        }));

        Ok(TpmDevice {
            command_tx: Some(command_tx),
            worker_handle,
        })
    }

    /// Sends a command to the worker thread and waits for the response.
    ///
    /// Displays a spinner on stderr if the operation takes more than one second.
    pub fn execute<C>(
        &mut self,
        command: &C,
        handles: Option<&[u32]>,
        sessions: &[tpm2_protocol::data::TpmsAuthCommand],
    ) -> TpmExecuteResult
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

        let (response_tx, response_rx) = mpsc::channel();
        self.command_tx
            .as_ref()
            .ok_or_else(|| TpmError::Execution("TPM worker disconnected".to_string()))?
            .send(TpmCommandMsg {
                command_bytes: command_buf[..len].to_vec(),
                command_code: C::COMMAND,
                response_tx,
            })
            .map_err(|_| TpmError::Execution("TPM work send failure".to_string()))?;

        let start_time = Instant::now();
        let mut spinner_active = false;
        let mut spinner_frame = 0;
        const SPINNER_FRAMES: &[char] = &['-', '\\', '|', '/'];
        const SPINNER_DELAY: Duration = Duration::from_millis(100);

        loop {
            match response_rx.try_recv() {
                Ok(result) => {
                    if spinner_active {
                        let _ = io::stderr().write_all(b"\r \r");
                        let _ = io::stderr().flush();
                    }
                    return result;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    return Err(TpmError::Execution(
                        "TPM disconnected unexpectedly".to_string(),
                    ));
                }
            }

            if start_time.elapsed() > Duration::from_secs(1) {
                spinner_active = true;
                let frame = SPINNER_FRAMES[spinner_frame];
                eprint!("\rTPM processing ... {frame} ");
                let _ = io::stderr().flush();
                spinner_frame = (spinner_frame + 1) % SPINNER_FRAMES.len();
            }

            thread::sleep(SPINNER_DELAY);
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

impl Drop for TpmDevice {
    fn drop(&mut self) {
        if let Some(tx) = self.command_tx.take() {
            drop(tx);
        }

        if let Some(handle) = self.worker_handle.take() {
            handle.join().expect("TPM worker thread panicked");
        }
    }
}
