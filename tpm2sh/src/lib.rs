// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use clap::Parser;
use clap_num::maybe_hex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    error::Error,
    fmt, fs,
    io::{BufRead, BufReader, Error as IoError, ErrorKind, Read, Write},
    vec::Vec,
};
use tpm2_protocol::{
    self,
    data::{self, Tpm2bAuth, TpmAlgId, TpmEccCurve, TpmRc, TpmRh, TpmtPublic},
    message::{
        TpmContextLoadCommand, TpmFlushContextCommand, TpmHeader, TpmLoadCommand,
        TpmReadPublicCommand,
    },
    TpmBuild, TpmErrorKind, TpmParse, TpmPersistent, TpmSession, TpmTransient, TpmWriter,
    TPM_MAX_COMMAND_SIZE,
};
use tracing::debug;

pub mod cli;
pub mod command;
pub mod crypto;
pub mod device;
pub mod formats;
pub mod policy;

pub use self::crypto::*;
pub use self::device::*;

pub(crate) fn parse_hex_u32(s: &str) -> Result<u32, TpmError> {
    maybe_hex(s).map_err(|e| TpmError::InvalidHandle(e.to_string()))
}

pub(crate) fn parse_persistent_handle(s: &str) -> Result<TpmPersistent, TpmError> {
    parse_hex_u32(s).map(TpmPersistent)
}

pub(crate) fn parse_tpm_rc(s: &str) -> Result<TpmRc, TpmError> {
    let raw_rc: u32 = maybe_hex(s).map_err(|e| TpmError::Execution(e.to_string()))?;
    Ok(TpmRc::try_from(raw_rc)?)
}

/// The callback API for subcommands
pub trait Command {
    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, device: &mut TpmDevice, session: Option<&AuthSession>) -> Result<(), TpmError>;
}

/// Parses command-line arguments and executes the corresponding command.
///
/// # Errors
///
/// Returns a `TpmError` if opening the device, or executing the command fails.
pub fn execute_cli() -> Result<(), TpmError> {
    let cli = crate::cli::Cli::parse();

    if let Some(command) = cli.command {
        let mut device = TpmDevice::new(&cli.device)?;
        let session = load_session(cli.session.as_deref())?;
        command.run(&mut device, session.as_ref())
    } else {
        println!("Options:");
        println!("  -d, --device <DEVICE>   [default: /dev/tpmrm0]");
        println!("      --session <SESSION> Authorization session context");
        println!("  -h, --help              Print help");
        println!("  -V, --version           Print version");
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgInfo {
    Rsa { key_bits: u16 },
    Ecc { curve_id: TpmEccCurve },
    KeyedHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alg {
    pub name: String,
    pub object_type: TpmAlgId,
    pub name_alg: TpmAlgId,
    pub params: AlgInfo,
}

impl TryFrom<&str> for Alg {
    type Error = String;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = name.split(':').collect();
        match parts.as_slice() {
            ["rsa", key_bits_str, name_alg_str] => {
                let key_bits: u16 = key_bits_str
                    .parse()
                    .map_err(|_| format!("invalid RSA key bits value: '{key_bits_str}'"))?;
                let name_alg = crate::tpm_alg_id_from_str(name_alg_str)?;
                Ok(Self {
                    name: name.to_string(),
                    object_type: TpmAlgId::Rsa,
                    name_alg,
                    params: AlgInfo::Rsa { key_bits },
                })
            }
            ["ecc", curve_id_str, name_alg_str] => {
                let curve_id = crate::tpm_ecc_curve_from_str(curve_id_str)?;
                let name_alg = crate::tpm_alg_id_from_str(name_alg_str)?;
                Ok(Self {
                    name: name.to_string(),
                    object_type: TpmAlgId::Ecc,
                    name_alg,
                    params: AlgInfo::Ecc { curve_id },
                })
            }
            ["keyedhash", name_alg_str] => {
                let name_alg = crate::tpm_alg_id_from_str(name_alg_str)?;
                Ok(Self {
                    name: name.to_string(),
                    object_type: TpmAlgId::KeyedHash,
                    name_alg,
                    params: AlgInfo::KeyedHash,
                })
            }
            _ => Err(format!("invalid algorithm format: '{name}'")),
        }
    }
}

impl Ord for Alg {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

impl PartialOrd for Alg {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Converts a user-friendly string to a `TpmAlgId`.
pub(crate) fn tpm_alg_id_from_str(s: &str) -> Result<TpmAlgId, String> {
    match s {
        "rsa" => Ok(TpmAlgId::Rsa),
        "sha1" => Ok(TpmAlgId::Sha1),
        "hmac" => Ok(TpmAlgId::Hmac),
        "aes" => Ok(TpmAlgId::Aes),
        "keyedhash" => Ok(TpmAlgId::KeyedHash),
        "xor" => Ok(TpmAlgId::Xor),
        "sha256" => Ok(TpmAlgId::Sha256),
        "sha384" => Ok(TpmAlgId::Sha384),
        "sha512" => Ok(TpmAlgId::Sha512),
        "null" => Ok(TpmAlgId::Null),
        "sm3_256" => Ok(TpmAlgId::Sm3_256),
        "sm4" => Ok(TpmAlgId::Sm4),
        "ecc" => Ok(TpmAlgId::Ecc),
        _ => Err(format!("Unsupported algorithm '{s}'")),
    }
}

/// Converts a `TpmAlgId` to its user-friendly string representation.
pub(crate) fn tpm_alg_id_to_str(alg: TpmAlgId) -> &'static str {
    match alg {
        TpmAlgId::Sha1 => "sha1",
        TpmAlgId::Sha256 => "sha256",
        TpmAlgId::Sha384 => "sha384",
        TpmAlgId::Sha512 => "sha512",
        TpmAlgId::Rsa => "rsa",
        TpmAlgId::Hmac => "hmac",
        TpmAlgId::Aes => "aes",
        TpmAlgId::KeyedHash => "keyedhash",
        TpmAlgId::Xor => "xor",
        TpmAlgId::Null => "null",
        TpmAlgId::Sm3_256 => "sm3_256",
        TpmAlgId::Sm4 => "sm4",
        TpmAlgId::Ecc => "ecc",
        _ => "unknown",
    }
}

/// Converts a user-friendly string to a `TpmEccCurve`.
pub(crate) fn tpm_ecc_curve_from_str(s: &str) -> Result<TpmEccCurve, String> {
    match s {
        "nist-p192" => Ok(TpmEccCurve::NistP192),
        "nist-p224" => Ok(TpmEccCurve::NistP224),
        "nist-p256" => Ok(TpmEccCurve::NistP256),
        "nist-p384" => Ok(TpmEccCurve::NistP384),
        "nist-p521" => Ok(TpmEccCurve::NistP521),
        _ => Err(format!("Unsupported ECC curve '{s}'")),
    }
}

/// Converts a `TpmEccCurve` to its user-friendly string representation.
pub(crate) fn tpm_ecc_curve_to_str(curve: TpmEccCurve) -> &'static str {
    match curve {
        TpmEccCurve::NistP192 => "nist-p192",
        TpmEccCurve::NistP224 => "nist-p224",
        TpmEccCurve::NistP256 => "nist-p256",
        TpmEccCurve::NistP384 => "nist-p384",
        TpmEccCurve::NistP521 => "nist-p521",
        TpmEccCurve::None => "none",
    }
}

/// Returns an iterator over all CLI-supported algorithm combinations.
pub fn enumerate_all() -> impl Iterator<Item = Alg> {
    let name_algs = [TpmAlgId::Sha256, TpmAlgId::Sha384, TpmAlgId::Sha512];
    let rsa_key_sizes = [2048, 3072, 4096];
    let ecc_curves = [
        TpmEccCurve::NistP256,
        TpmEccCurve::NistP384,
        TpmEccCurve::NistP521,
    ];

    let rsa_iter = rsa_key_sizes.into_iter().flat_map(move |key_bits| {
        name_algs.into_iter().map(move |name_alg| Alg {
            name: format!("rsa:{}:{}", key_bits, tpm_alg_id_to_str(name_alg)),
            object_type: TpmAlgId::Rsa,
            name_alg,
            params: AlgInfo::Rsa { key_bits },
        })
    });

    let ecc_iter = ecc_curves.into_iter().flat_map(move |curve_id| {
        name_algs.into_iter().map(move |name_alg| Alg {
            name: format!(
                "ecc:{}:{}",
                tpm_ecc_curve_to_str(curve_id),
                tpm_alg_id_to_str(name_alg)
            ),
            object_type: TpmAlgId::Ecc,
            name_alg,
            params: AlgInfo::Ecc { curve_id },
        })
    });

    let keyedhash_iter = name_algs.into_iter().map(move |name_alg| Alg {
        name: format!("keyedhash:{}", tpm_alg_id_to_str(name_alg)),
        object_type: TpmAlgId::KeyedHash,
        name_alg,
        params: AlgInfo::KeyedHash,
    });

    rsa_iter.chain(ecc_iter).chain(keyedhash_iter)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Envelope {
    pub version: u32,
    #[serde(rename = "type")]
    pub object_type: String,
    pub data: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionData {
    pub handle: u32,
    pub nonce_tpm: String,
    pub attributes: u8,
    pub hmac_key: String,
    pub auth_hash: u16,
    pub policy_digest: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ObjectData {
    pub oid: String,
    pub empty_auth: bool,
    pub parent: String,
    pub public: String,
    pub private: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ContextData {
    pub context_blob: String,
}

/// Deserializes an `Envelope`-wrapped JSON object from a string.
///
/// # Errors
///
/// Returns a `TpmError::Json` if deserialization fails or if the object type
/// in the envelope does not match `expected_type`.
pub fn from_json_str<T>(json_str: &str, expected_type: &str) -> Result<T, TpmError>
where
    T: for<'a> serde::Deserialize<'a>,
{
    let envelope: Envelope =
        serde_json::from_str(json_str).map_err(|e| TpmError::Json(e.to_string()))?;
    if envelope.object_type != expected_type {
        return Err(TpmError::Json(format!(
            "invalid object type: expected '{}', got '{}'",
            expected_type, envelope.object_type
        )));
    }
    serde_json::from_value(envelope.data).map_err(|e| TpmError::Json(e.to_string()))
}

/// Serializes a TPM data data and writes it to a file.
///
/// # Errors
///
/// Returns a `TpmError` if serialization fails or the file cannot be written.
pub fn write_to_file<T: TpmBuild>(path: &str, obj: &T) -> Result<(), TpmError> {
    let mut buffer = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buffer);
        obj.build(&mut writer)?;
        writer.len()
    };
    fs::write(path, &buffer[..len]).map_err(|e| TpmError::File(path.to_string(), e))
}

/// Reads from a file and deserializes it into a TPM data data.
///
/// # Errors
///
/// Returns a `TpmError` if the file cannot be read, or if the file content
/// cannot be parsed into the target type `T`, including if there is trailing data.
pub fn read_from_file<T>(path: &str) -> Result<T, TpmError>
where
    T: for<'a> TpmParse<'a>,
{
    let bytes = fs::read(path).map_err(|e| TpmError::File(path.to_string(), e))?;
    let (obj, remainder) = T::parse(&bytes)?;
    if !remainder.is_empty() {
        return Err(TpmError::Parse(
            "file contained trailing data after the expected object".to_string(),
        ));
    }
    Ok(obj)
}

/// Manages the streaming I/O for a command in the JSON Lines pipeline.
pub struct CommandIo<'a, W: Write> {
    writer: W,
    input_objects: Vec<cli::Object>,
    output_objects: Vec<cli::Object>,
    pub session: Option<&'a AuthSession>,
}

impl<'a, W: Write> CommandIo<'a, W> {
    /// Creates a new command context for the pipeline.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if reading from the input stream fails.
    pub fn new<R: Read>(
        reader: R,
        writer: W,
        session: Option<&'a AuthSession>,
    ) -> Result<Self, TpmError> {
        let mut input_objects = Vec::new();
        let buf_reader = BufReader::new(reader);
        for line in buf_reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                input_objects.push(serde_json::from_str(&line)?);
            }
        }
        Ok(Self {
            writer,
            input_objects,
            output_objects: Vec::new(),
            session,
        })
    }

    /// Finds and removes the first object from the input pipeline that matches a predicate.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if no matching object is found.
    pub fn consume_object<F>(&mut self, predicate: F) -> Result<cli::Object, TpmError>
    where
        F: FnMut(&cli::Object) -> bool,
    {
        let pos = self
            .input_objects
            .iter()
            .position(predicate)
            .ok_or_else(|| {
                TpmError::Execution("required object not found in input pipeline".to_string())
            })?;
        Ok(self.input_objects.remove(pos))
    }

    /// Adds an object to be written to the output stream upon finalization.
    pub fn push_object(&mut self, obj: cli::Object) {
        self.output_objects.push(obj);
    }

    /// Finalizes the command, writing all new and unconsumed objects to the output stream.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if JSON serialization or I/O fails.
    pub fn finalize(mut self) -> Result<(), TpmError> {
        let mut final_objects = self.input_objects;
        final_objects.append(&mut self.output_objects);

        for obj in final_objects {
            let json_str = serde_json::to_string(&obj)?;
            writeln!(self.writer, "{json_str}")?;
        }
        Ok(())
    }
}

/// Pops an object from the stack and deserializes it into `ObjectData`.
///
/// # Errors
///
/// Returns a `TpmError` if the stack is empty, the object is not a context,
/// or the data cannot be parsed.
pub fn pop_object_data<W: Write>(io: &mut CommandIo<W>) -> Result<ObjectData, TpmError> {
    let obj = io.consume_object(|obj| {
        if let cli::Object::Context(v) = obj {
            if let Ok(env) = serde_json::from_value::<Envelope>(v.clone()) {
                return env.object_type == "object";
            }
        }
        false
    })?;

    let crate::cli::Object::Context(envelope_value) = obj else {
        unreachable!()
    };

    let envelope: Envelope = serde_json::from_value(envelope_value)?;
    serde_json::from_value(envelope.data).map_err(|e| TpmError::Json(e.to_string()))
}

/// Parses a parent handle from a hex string in the loaded object data.
///
/// # Errors
///
/// Returns a `TpmError::Parse` if the hex string is invalid.
pub fn parse_parent_handle_from_json(object_data: &ObjectData) -> Result<TpmTransient, TpmError> {
    u32::from_str_radix(object_data.parent.trim_start_matches("0x"), 16)
        .map_err(|e| TpmError::Parse(e.to_string()))
        .map(TpmTransient)
}

/// Loads a TPM object, executes an operation with its handle, and ensures it's flushed.
///
/// This helper abstracts the common pattern:
/// 1. Load a key/object from its public and private parts under a parent.
/// 2. Execute a given closure with the handle of the newly loaded transient object.
/// 3. Automatically flush the transient object's context after the operation completes.
///
/// # Errors
///
/// Returns the error from the primary operation (`op`). If `op` succeeds but
/// the subsequent flush fails, the flush error is returned instead.
#[allow(clippy::module_name_repetitions)]
pub fn with_loaded_object<F, R>(
    chip: &mut TpmDevice,
    parent_handle: TpmTransient,
    parent_auth: &cli::AuthArgs,
    session: Option<&AuthSession>,
    in_public: data::Tpm2bPublic,
    in_private: data::Tpm2bPrivate,
    op: F,
) -> Result<R, TpmError>
where
    F: FnOnce(&mut TpmDevice, TpmTransient) -> Result<R, TpmError>,
{
    let load_cmd = TpmLoadCommand {
        in_private,
        in_public,
    };
    let parent_handles = [parent_handle.into()];
    let parent_sessions = get_auth_sessions(
        &load_cmd,
        &parent_handles,
        session,
        parent_auth.auth.as_deref(),
    )?;

    let (load_resp, _) = chip.execute(&load_cmd, Some(&parent_handles), &parent_sessions)?;
    let load_resp = load_resp
        .Load()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    let object_handle = load_resp.object_handle;

    let op_result = op(chip, object_handle);

    let flush_cmd = TpmFlushContextCommand {
        flush_handle: object_handle.into(),
    };
    let flush_err = chip.execute(&flush_cmd, Some(&[]), &[]).err();

    if let Some(e) = flush_err {
        tracing::debug!(handle = ?object_handle, error = %e, "failed to flush object context after operation");
        if op_result.is_ok() {
            return Err(e);
        }
    }

    op_result
}

/// Resolves an input string with "data:" or "path:" prefixes into raw bytes.
///
/// # Errors
///
/// Returns a `TpmError` if the prefix is invalid or I/O fails.
pub fn input_to_bytes(s: &str) -> Result<Vec<u8>, TpmError> {
    if let Some(data_str) = s.strip_prefix("data:") {
        hex::decode(data_str).map_err(|e| TpmError::Parse(e.to_string()))
    } else if let Some(path_str) = s.strip_prefix("path:") {
        fs::read(path_str).map_err(|e| TpmError::File(path_str.to_string(), e))
    } else {
        fs::read(s).map_err(|e| TpmError::File(s.to_string(), e))
    }
}

/// Resolves an input string with "data:" or "path:" prefixes into a UTF-8 string.
///
/// # Errors
///
/// Returns a `TpmError` if the prefix is invalid, I/O fails, or the data is not valid UTF-8.
pub fn input_to_utf8(s: &str) -> Result<String, TpmError> {
    if let Some(data_str) = s.strip_prefix("data:") {
        let bytes = hex::decode(data_str).map_err(|e| TpmError::Parse(e.to_string()))?;
        String::from_utf8(bytes).map_err(|e| TpmError::Parse(e.to_string()))
    } else if let Some(path_str) = s.strip_prefix("path:") {
        fs::read_to_string(path_str).map_err(|e| TpmError::File(path_str.to_string(), e))
    } else {
        fs::read_to_string(s).map_err(|e| TpmError::File(s.to_string(), e))
    }
}

/// Resolves an object from the input stack into a transient handle.
///
/// If the object is a context file, it is loaded into the TPM and its handle is
/// returned. The loaded object is temporary and will be flushed on TPM reset.
///
/// # Errors
///
/// Returns a `TpmError` if the object is of an invalid type or cannot be loaded.
pub fn object_to_handle(chip: &mut TpmDevice, obj: &cli::Object) -> Result<TpmTransient, TpmError> {
    match obj {
        cli::Object::Handle(handle) => Ok(*handle),
        cli::Object::Persistent(handle) => Ok(TpmTransient(handle.0)),
        cli::Object::Context(v) => {
            let s = v.as_str().ok_or_else(|| {
                TpmError::Parse("context object must contain a string value".to_string())
            })?;
            let context_blob = input_to_bytes(s)?;
            let (context, _) = data::TpmsContext::parse(&context_blob)?;
            let load_cmd = TpmContextLoadCommand { context };
            let (resp, _) = chip.execute(&load_cmd, None, &[])?;
            let load_resp = resp
                .ContextLoad()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
            Ok(load_resp.loaded_handle)
        }
        cli::Object::Pcrs(_) => Err(TpmError::Execution(
            "cannot convert a PCR object to a handle".to_string(),
        )),
    }
}

/// Reads the public area and name of a TPM object.
///
/// # Errors
///
/// Returns `TpmError` if the `ReadPublic` command fails.
pub fn read_public(
    chip: &mut TpmDevice,
    handle: TpmTransient,
) -> Result<(TpmtPublic, data::Tpm2bName), TpmError> {
    let cmd = TpmReadPublicCommand {};
    let (resp, _) = chip.execute(&cmd, Some(&[handle.into()]), &[])?;
    let read_public_resp = resp
        .ReadPublic()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    Ok((read_public_resp.out_public.inner, read_public_resp.name))
}

/// Manages the state of an active authorization session.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub handle: TpmSession,
    pub nonce_tpm: data::Tpm2bNonce,
    pub attributes: data::TpmaSession,
    pub hmac_key: data::Tpm2bAuth,
    pub auth_hash: data::TpmAlgId,
}

/// Loads a session from the CLI `--session` argument or the `TPM2_SESSION` environment variable.
///
/// # Errors
///
/// Returns `TpmError` if the session source cannot be read or parsed.
pub fn load_session(session_arg: Option<&str>) -> Result<Option<AuthSession>, TpmError> {
    let session_str = match session_arg {
        Some(s) => Some(s.to_string()),
        None => std::env::var("TPM2_SESSION").ok(),
    };

    let Some(session_str) = session_str else {
        return Ok(None);
    };

    let json_str = if session_str.trim().starts_with('{') {
        session_str
    } else {
        fs::read_to_string(&session_str).map_err(|e| TpmError::File(session_str.to_string(), e))?
    };

    let data: SessionData = from_json_str(&json_str, "session")?;

    Ok(Some(AuthSession {
        handle: TpmSession(data.handle),
        nonce_tpm: data::Tpm2bNonce::try_from(
            base64_engine
                .decode(data.nonce_tpm)
                .map_err(|e| TpmError::Parse(e.to_string()))?
                .as_slice(),
        )?,
        attributes: data::TpmaSession::from_bits_truncate(data.attributes),
        hmac_key: data::Tpm2bAuth::try_from(
            base64_engine
                .decode(data.hmac_key)
                .map_err(|e| TpmError::Parse(e.to_string()))?
                .as_slice(),
        )?,
        auth_hash: data::TpmAlgId::try_from(data.auth_hash)
            .map_err(|()| TpmError::Parse("invalid auth_hash in session data".to_string()))?,
    }))
}

/// Builds the authorization area for a password-based session.
///
/// # Errors
///
/// Returns `TpmError` on failure.
pub fn build_password_session(auth: Option<&str>) -> Result<Vec<data::TpmsAuthCommand>, TpmError> {
    match auth {
        Some(password) => {
            debug!(auth_len = password.len(), "building password session");
            Ok(vec![data::TpmsAuthCommand {
                session_handle: TpmSession(TpmRh::Password as u32),
                nonce: data::Tpm2bNonce::default(),
                session_attributes: data::TpmaSession::empty(),
                hmac: Tpm2bAuth::try_from(password.as_bytes())?,
            }])
        }
        None => Ok(Vec::new()),
    }
}

/// Prepares the authorization sessions for a command, handling either a full
/// `AuthSession` context or a simple password.
///
/// # Errors
///
/// Returns a `TpmError` if building the command parameters or creating the
/// authorization HMAC fails.
pub fn get_auth_sessions<'a, C>(
    command: &C,
    handles: &[u32],
    session: Option<&'a AuthSession>,
    password: Option<&'a str>,
) -> Result<Vec<data::TpmsAuthCommand>, TpmError>
where
    C: for<'b> TpmHeader<'b>,
{
    if let Some(session) = session {
        let params = build_to_vec(command)?;

        let nonce_size = tpm2_protocol::tpm_hash_size(&session.auth_hash).ok_or_else(|| {
            TpmError::Execution(format!(
                "session has an invalid hash algorithm: {}",
                session.auth_hash
            ))
        })?;

        let mut nonce_bytes = vec![0; nonce_size];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce_caller = data::Tpm2bNonce::try_from(nonce_bytes.as_slice())?;

        let auth = create_auth(session, &nonce_caller, C::COMMAND, handles, &params)?;
        Ok(vec![auth])
    } else {
        let effective_password = if C::WITH_SESSIONS && password.is_none() {
            Some("")
        } else {
            password
        };
        build_password_session(effective_password)
    }
}

#[derive(Debug)]
pub enum TpmError {
    Build(TpmErrorKind),
    Execution(String),
    File(String, IoError),
    InvalidHandle(String),
    Io(ErrorKind),
    Json(String),
    Parse(String),
    PcrSelection(String),
    TpmRc(TpmRc),
    UnexpectedResponse(String),
}

impl Error for TpmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let TpmError::File(_, err) = self {
            Some(err)
        } else {
            None
        }
    }
}

impl From<IoError> for TpmError {
    fn from(err: IoError) -> Self {
        TpmError::Io(err.kind())
    }
}

impl From<TpmErrorKind> for TpmError {
    fn from(err: TpmErrorKind) -> Self {
        TpmError::Build(err)
    }
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::Build(err) => write!(f, "error=build, details='{err}'"),
            TpmError::Execution(reason) => write!(f, "error=cli, reason='{reason}'"),
            TpmError::File(path, err) => write!(f, "error=io, path={path}, details='{err}'"),
            TpmError::Io(kind) => write!(f, "error=io, kind={kind:?}"),
            TpmError::InvalidHandle(handle) => {
                write!(f, "error=cli, reason='invalid handle: {handle}'")
            }
            TpmError::Json(reason) => write!(f, "error=json, reason='{reason}'"),
            TpmError::Parse(reason) => write!(f, "error=parse, reason='{reason}'"),
            TpmError::PcrSelection(reason) => write!(f, "error=pcr, reason='{reason}'"),
            TpmError::TpmRc(rc) => write!(f, "error=tpm, rc='{rc}'"),
            TpmError::UnexpectedResponse(reason) => {
                write!(f, "error=cli, reason='unexpected response type: {reason}'")
            }
        }
    }
}

/// A helper to build a `TpmBuild` type into a `Vec<u8>`.
pub(crate) fn build_to_vec<T: TpmBuild>(obj: &T) -> Result<Vec<u8>, TpmError> {
    let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        obj.build(&mut writer)?;
        writer.len()
    };
    Ok(buf[..len].to_vec())
}

impl From<pkcs8::der::Error> for TpmError {
    fn from(err: pkcs8::der::Error) -> Self {
        TpmError::Execution(err.to_string())
    }
}

impl From<serde_json::Error> for TpmError {
    fn from(err: serde_json::Error) -> Self {
        TpmError::Json(err.to_string())
    }
}

/// Gets the number of PCRs from the TPM.
pub(crate) fn get_pcr_count(chip: &mut TpmDevice) -> Result<usize, TpmError> {
    let cap_data = chip.get_capability(data::TpmCap::Pcrs, 0, device::TPM_CAP_PROPERTY_MAX)?;
    let Some(first_cap) = cap_data.into_iter().next() else {
        return Err(TpmError::Execution(
            "TPM reported no capabilities for PCRs.".to_string(),
        ));
    };

    if let data::TpmuCapabilities::Pcrs(pcrs) = first_cap.data {
        if let Some(first_bank) = pcrs.iter().next() {
            Ok(first_bank.pcr_select.len() * 8)
        } else {
            Err(TpmError::Execution(
                "TPM reported no active PCR banks.".to_string(),
            ))
        }
    } else {
        Err(TpmError::Execution(
            "Unexpected capability data type when querying for PCRs.".to_string(),
        ))
    }
}

/// Parses a PCR selection string (e.g., "sha256:0,7+sha1:1") into a TPM list.
pub(crate) fn parse_pcr_selection(
    selection_str: &str,
    pcr_count: usize,
) -> Result<data::TpmlPcrSelection, TpmError> {
    let pcr_select_size = pcr_count.div_ceil(8);
    if pcr_select_size > data::TPM_PCR_SELECT_MAX {
        return Err(TpmError::PcrSelection(format!(
            "required pcr select size {pcr_select_size} exceeds maximum {}",
            data::TPM_PCR_SELECT_MAX
        )));
    }

    let mut list = data::TpmlPcrSelection::new();
    for bank_str in selection_str.split('+') {
        let (alg_str, pcrs_str) = bank_str
            .split_once(':')
            .ok_or_else(|| TpmError::PcrSelection(format!("invalid bank format: {bank_str}")))?;

        let alg = crate::tpm_alg_id_from_str(alg_str).map_err(TpmError::PcrSelection)?;

        let mut pcr_select_bytes = vec![0u8; pcr_select_size];
        for pcr_str in pcrs_str.split(',') {
            let pcr_index: usize = pcr_str
                .parse()
                .map_err(|_| TpmError::PcrSelection(format!("invalid pcr index: {pcr_str}")))?;
            if pcr_index >= pcr_count {
                return Err(TpmError::PcrSelection(format!(
                    "pcr index {pcr_index} is out of range for a TPM with {pcr_count} PCRs"
                )));
            }
            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }

        list.try_push(data::TpmsPcrSelection {
            hash: alg,
            pcr_select: tpm2_protocol::TpmBuffer::try_from(pcr_select_bytes.as_slice())?,
        })?;
    }
    Ok(list)
}
