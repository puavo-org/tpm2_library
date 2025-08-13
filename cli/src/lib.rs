// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use clap::Parser;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    error::Error,
    fmt, fs,
    io::{self, BufRead, BufReader, Error as IoError, ErrorKind, Read, Write},
    vec::Vec,
};
use tpm2_protocol::{
    self,
    data::{self, Tpm2bAuth, TpmAlgId, TpmEccCurve, TpmRc, TpmRh, TpmtPublic},
    message::{
        TpmContextLoadCommand, TpmFlushContextCommand, TpmHeader, TpmLoadCommand,
        TpmReadPublicCommand,
    },
    TpmBuild, TpmErrorKind, TpmParse, TpmSession, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
};
use tracing::debug;

pub mod cli;
pub mod command;
pub mod crypto;
pub mod device;

pub use self::crypto::*;
pub use self::device::*;

/// Parses command-line arguments and executes the corresponding command.
///
/// # Errors
///
/// Returns a `TpmError` if opening the device, or executing the command fails.
pub fn execute_cli() -> Result<(), TpmError> {
    let cli = crate::cli::Cli::parse();

    let Some(command) = cli.command else {
        println!("A command is required.");
        println!("For a list of commands, run 'tpm2 --help'.");
        return Ok(());
    };

    let mut device = TpmDevice::open(&cli.device)?;
    let session = load_session(cli.session.as_deref())?;

    match &command {
        crate::cli::Commands::CreatePrimary(args) => {
            crate::command::create_primary::run(&mut device, args, session.as_ref())
        }
        crate::cli::Commands::Save(args) => {
            crate::command::save::run(&mut device, args, session.as_ref())
        }
        crate::cli::Commands::Delete(args) => {
            crate::command::delete::run(&mut device, args, session.as_ref())
        }
        crate::cli::Commands::Import(args) => {
            crate::command::import::run(&mut device, args, session.as_ref())
        }
        crate::cli::Commands::Algorithms(args) => {
            crate::command::algorithms::run(&mut device, args)
        }
        crate::cli::Commands::Objects => crate::command::objects::run(&mut device),
        crate::cli::Commands::Load(args) => {
            crate::command::load::run(&mut device, args, session.as_ref())
        }
        crate::cli::Commands::PcrEvent(args) => {
            crate::command::pcr_event::run(&mut device, args, session.as_ref())
        }
        crate::cli::Commands::PcrRead(args) => crate::command::pcr_read::run(&mut device, args),
        crate::cli::Commands::PrintError(args) => {
            crate::command::print_error::run(args.rc);
            Ok(())
        }
        crate::cli::Commands::ResetLock(args) => {
            crate::command::reset_lock::run(&mut device, args, session.as_ref())
        }
        crate::cli::Commands::Seal(args) => {
            crate::command::seal::run(&mut device, args, session.as_ref())
        }
        crate::cli::Commands::StartAuthSession(args) => {
            crate::command::start_session::run(&mut device, args)
        }
        crate::cli::Commands::Unseal(args) => {
            crate::command::unseal::run(&mut device, args, session.as_ref())
        }
        crate::cli::Commands::Convert(args) => crate::command::convert::run(args),
        crate::cli::Commands::PolicySecret(args) => {
            crate::command::policy_secret::run(&mut device, args, session.as_ref())
        }
        crate::cli::Commands::PolicyPcr(args) => {
            crate::command::policy_pcr::run(args, session.as_ref())
        }
        crate::cli::Commands::PolicyOr(args) => {
            crate::command::policy_or::run(args, session.as_ref())
        }
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
        TpmEccCurve::None => unreachable!("TpmEccCurve::None should not be converted to a string"),
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

/// Reads a session file and deserializes it into `SessionData`.
pub(crate) fn read_session_data_from_file(path: &str) -> Result<SessionData, TpmError> {
    let json_str = fs::read_to_string(path).map_err(|e| TpmError::File(path.to_string(), e))?;
    from_json_str(&json_str, "session")
}

/// Reads all bytes from an input path or stdin.
///
/// If path is \"-\", reads from stdin. Otherwise, reads from the specified file.
///
/// # Errors
///
/// Returns `TpmError::File` on I/O errors.
pub fn read_input(path: Option<&str>) -> Result<Vec<u8>, TpmError> {
    let mut buf = Vec::new();
    match path {
        Some("-") | None => {
            io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| TpmError::File("stdin".to_string(), e))?;
        }
        Some(file_path) => {
            fs::File::open(file_path)
                .and_then(|mut f| f.read_to_end(&mut buf))
                .map_err(|e| TpmError::File(file_path.to_string(), e))?;
        }
    }
    Ok(buf)
}

/// Manages the streaming I/O for a command in the JSON Lines pipeline.
pub struct CommandIo<'a, R: Read, W: Write> {
    reader: BufReader<R>,
    writer: W,
    output_objects: Vec<cli::Object>,
    pub session: Option<&'a AuthSession>,
}

impl<'a, R: Read, W: Write> CommandIo<'a, R, W> {
    /// Creates a new command context for the pipeline.
    pub fn new(reader: R, writer: W, session: Option<&'a AuthSession>) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            output_objects: Vec::new(),
            session,
        }
    }

    /// Reads and parses the next JSON object from the input stream.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the stream is empty, or if I/O or JSON parsing fails.
    pub fn next_object(&mut self) -> Result<cli::Object, TpmError> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Err(TpmError::Execution(
                "command requires an object from the input pipeline, but received none".to_string(),
            ));
        }
        serde_json::from_str(&line).map_err(|e| TpmError::Json(e.to_string()))
    }

    /// Adds an object to be written to the output stream upon finalization.
    pub fn push_object(&mut self, obj: cli::Object) {
        self.output_objects.push(obj);
    }

    /// Finalizes the command by writing all pushed objects to the output stream.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if JSON serialization or I/O fails.
    pub fn finalize(mut self) -> Result<(), TpmError> {
        for obj in self.output_objects {
            let json_str =
                serde_json::to_string(&obj).map_err(|e| TpmError::Json(e.to_string()))?;
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
pub fn pop_object_data(io: &mut CommandIo<impl Read, impl Write>) -> Result<ObjectData, TpmError> {
    let obj = io.next_object()?;
    let data_string = match obj {
        crate::cli::Object::Context(s) => resolve_string_input(&s)
            .and_then(|bytes| String::from_utf8(bytes).map_err(|e| TpmError::Parse(e.to_string()))),
        _ => Err(TpmError::Execution(
            "expected a context object on the stack".to_string(),
        )),
    }?;
    from_json_str(&data_string, "object")
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
pub fn resolve_string_input(s: &str) -> Result<Vec<u8>, TpmError> {
    if let Some(data_str) = s.strip_prefix("data:") {
        hex::decode(data_str).map_err(|e| TpmError::Parse(e.to_string()))
    } else if let Some(path_str) = s.strip_prefix("path:") {
        fs::read(path_str).map_err(|e| TpmError::File(path_str.to_string(), e))
    } else {
        fs::read(s).map_err(|e| TpmError::File(s.to_string(), e))
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
pub fn resolve_object_handle(
    chip: &mut TpmDevice,
    obj: &cli::Object,
) -> Result<TpmTransient, TpmError> {
    match obj {
        cli::Object::Handle(handle) => Ok(*handle),
        cli::Object::Persistent(handle) => Ok(TpmTransient(handle.0)),
        cli::Object::Context(s) => {
            let context_blob = resolve_string_input(s)?;
            let (context, _) = data::TpmsContext::parse(&context_blob)?;
            let load_cmd = TpmContextLoadCommand { context };
            let (resp, _) = chip.execute(&load_cmd, None, &[])?;
            let load_resp = resp
                .ContextLoad()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
            Ok(load_resp.loaded_handle)
        }
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
        let params = command.build_to_vec()?;

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
        let effective_password =
            if C::TAG == tpm2_protocol::data::TpmSt::Sessions && password.is_none() {
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

/// A local trait to provide `build_to_vec` on any `TpmBuild` type.
pub(crate) trait BuildToVec: TpmBuild {
    fn build_to_vec(&self) -> Result<Vec<u8>, TpmError> {
        let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            self.build(&mut writer)?;
            writer.len()
        };
        Ok(buf[..len].to_vec())
    }
}
impl<T: TpmBuild> BuildToVec for T {}

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
