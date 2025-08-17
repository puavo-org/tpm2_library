// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli, CommandIo, TpmDevice, TpmError};
use json::JsonValue;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write};
use tpm2_protocol::{
    self,
    data::{self, TpmRc},
    message::TpmContextLoadCommand,
    TpmBuild, TpmParse, TpmPersistent, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

pub(crate) fn parse_hex_u32(s: &str) -> Result<u32, TpmError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).map_err(TpmError::from)
}

pub(crate) fn parse_persistent_handle(s: &str) -> Result<TpmPersistent, TpmError> {
    parse_hex_u32(s).map(TpmPersistent)
}

pub(crate) fn parse_tpm_rc(s: &str) -> Result<TpmRc, TpmError> {
    let raw_rc: u32 = parse_hex_u32(s)?;
    Ok(TpmRc::try_from(raw_rc)?)
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
pub fn from_json_str(json_str: &str, expected_type: &str) -> Result<JsonValue, TpmError> {
    let parsed = json::parse(json_str).map_err(|e| TpmError::Parse(e.to_string()))?;
    let obj_type = parsed["type"]
        .as_str()
        .ok_or_else(|| TpmError::Parse("'type' field is not a string".to_string()))?;
    if obj_type != expected_type {
        return Err(TpmError::Execution(format!(
            "invalid object type: expected '{expected_type}', got '{obj_type}'"
        )));
    }
    Ok(parsed["data"].clone())
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
    serde_json::from_value(envelope.data).map_err(Into::into)
}

/// Parses a parent handle from a hex string in the loaded object data.
///
/// # Errors
///
/// Returns a `TpmError::Parse` if the hex string is invalid.
pub fn parse_parent_handle_from_json(object_data: &ObjectData) -> Result<TpmTransient, TpmError> {
    u32::from_str_radix(object_data.parent.trim_start_matches("0x"), 16)
        .map_err(Into::into)
        .map(TpmTransient)
}

/// Resolves an input string with "data:" or "path:" prefixes into raw bytes.
///
/// # Errors
///
/// Returns a `TpmError` if the prefix is invalid or I/O fails.
pub fn input_to_bytes(s: &str) -> Result<Vec<u8>, TpmError> {
    if let Some(data_str) = s.strip_prefix("data:") {
        hex::decode(data_str).map_err(Into::into)
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
        let bytes = hex::decode(data_str)?;
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
pub fn object_to_handle(
    chip: &mut TpmDevice,
    obj: &cli::Object,
    log_format: cli::LogFormat,
) -> Result<TpmTransient, TpmError> {
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
            let (resp, _) = chip.execute(&load_cmd, None, &[], log_format)?;
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
