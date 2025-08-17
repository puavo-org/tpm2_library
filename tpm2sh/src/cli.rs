// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{formats::PcrOutput, Alg, Command, TpmError};
use std::str::FromStr;
use tpm2_protocol::{
    data::{TpmCap, TpmRc, TpmRh, TpmuCapabilities},
    TpmPersistent, TpmTransient,
};

#[derive(Debug, Clone)]
pub enum Object {
    Handle(TpmTransient),
    Persistent(TpmPersistent),
    Context(json::JsonValue),
    Pcrs(PcrOutput),
}

impl Object {
    #[must_use]
    pub fn to_json(&self) -> json::JsonValue {
        match self {
            Object::Handle(h) => json::object! { "handle": format!("{:#010x}", u32::from(*h)) },
            Object::Persistent(p) => {
                json::object! { "persistent": format!("{:#010x}", u32::from(*p)) }
            }
            Object::Context(c) => json::object! { "context": c.clone() },
            Object::Pcrs(p) => json::object! { "pcrs": p.to_json() },
        }
    }

    /// Deserializes an `Object` from a `json::JsonValue`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::Parse` if the JSON object is malformed, has an
    /// unknown key, or contains values of the wrong type.
    pub fn from_json(value: &json::JsonValue) -> Result<Self, TpmError> {
        if !value.is_object() {
            return Err(TpmError::Parse("expected a JSON object".to_string()));
        }

        let (key, value) = value
            .entries()
            .next()
            .ok_or_else(|| TpmError::Parse("object is empty".to_string()))?;

        match key {
            "handle" => {
                let s = value
                    .as_str()
                    .ok_or_else(|| TpmError::Parse("handle value is not a string".to_string()))?;
                let handle = crate::parse_hex_u32(s).map(TpmTransient)?;
                Ok(Object::Handle(handle))
            }
            "persistent" => {
                let s = value.as_str().ok_or_else(|| {
                    TpmError::Parse("persistent value is not a string".to_string())
                })?;
                let handle = crate::parse_persistent_handle(s)?;
                Ok(Object::Persistent(handle))
            }
            "context" => Ok(Object::Context(value.clone())),
            "pcrs" => {
                let pcrs = PcrOutput::from_json(value)?;
                Ok(Object::Pcrs(pcrs))
            }
            _ => Err(TpmError::Parse(format!("unknown object key: {key}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum LogFormat {
    #[default]
    Plain,
    Pretty,
}

impl FromStr for LogFormat {
    type Err = TpmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plain" => Ok(Self::Plain),
            "pretty" => Ok(Self::Pretty),
            _ => Err(TpmError::Execution(format!("invalid log format: {s}"))),
        }
    }
}

#[derive(Debug, Default)]
pub struct Cli {
    pub device: String,
    pub log_format: LogFormat,
    pub command: Option<Commands>,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum Hierarchy {
    #[default]
    Owner,
    Platform,
    Endorsement,
}

impl FromStr for Hierarchy {
    type Err = TpmError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(Hierarchy::Owner),
            "platform" => Ok(Hierarchy::Platform),
            "endorsement" => Ok(Hierarchy::Endorsement),
            _ => Err(TpmError::Execution(format!("invalid hierarchy: {s}"))),
        }
    }
}

impl From<Hierarchy> for TpmRh {
    fn from(h: Hierarchy) -> Self {
        match h {
            Hierarchy::Owner => TpmRh::Owner,
            Hierarchy::Platform => TpmRh::Platform,
            Hierarchy::Endorsement => TpmRh::Endorsement,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SessionType {
    #[default]
    Hmac,
    Policy,
    Trial,
}

impl FromStr for SessionType {
    type Err = TpmError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hmac" => Ok(SessionType::Hmac),
            "policy" => Ok(SessionType::Policy),
            "trial" => Ok(SessionType::Trial),
            _ => Err(TpmError::Execution(format!("invalid session type: {s}"))),
        }
    }
}

impl From<SessionType> for tpm2_protocol::data::TpmSe {
    fn from(val: SessionType) -> Self {
        match val {
            SessionType::Hmac => Self::Hmac,
            SessionType::Policy => Self::Policy,
            SessionType::Trial => Self::Trial,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum SessionHashAlg {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

impl FromStr for SessionHashAlg {
    type Err = TpmError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha256" => Ok(SessionHashAlg::Sha256),
            "sha384" => Ok(SessionHashAlg::Sha384),
            "sha512" => Ok(SessionHashAlg::Sha512),
            _ => Err(TpmError::Execution(format!(
                "invalid session hash algorithm: {s}"
            ))),
        }
    }
}

impl From<SessionHashAlg> for tpm2_protocol::data::TpmAlgId {
    fn from(alg: SessionHashAlg) -> Self {
        match alg {
            SessionHashAlg::Sha256 => Self::Sha256,
            SessionHashAlg::Sha384 => Self::Sha384,
            SessionHashAlg::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyFormat {
    #[default]
    Json,
    Pem,
    Der,
}

impl FromStr for KeyFormat {
    type Err = TpmError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(KeyFormat::Json),
            "pem" => Ok(KeyFormat::Pem),
            "der" => Ok(KeyFormat::Der),
            _ => Err(TpmError::Execution(format!("invalid key format: {s}"))),
        }
    }
}

#[derive(Debug)]
pub enum Commands {
    Algorithms(Algorithms),
    Convert(Convert),
    CreatePrimary(CreatePrimary),
    Delete(Delete),
    Import(Import),
    Load(Load),
    Objects(Objects),
    PcrEvent(PcrEvent),
    PcrRead(PcrRead),
    Policy(Policy),
    PrintError(PrintError),
    ResetLock(ResetLock),
    Save(Save),
    Seal(Seal),
    StartSession(StartSession),
    Unseal(Unseal),
}

impl Command for Commands {
    fn help()
    where
        Self: Sized,
    {
        unimplemented!();
    }

    fn parse(_parser: &mut lexopt::Parser) -> Result<Self, TpmError>
    where
        Self: Sized,
    {
        unimplemented!();
    }

    fn run(
        &self,
        device: &mut crate::TpmDevice,
        log_format: crate::cli::LogFormat,
    ) -> Result<(), crate::TpmError> {
        match self {
            Self::Algorithms(args) => args.run(device, log_format),
            Self::Convert(args) => args.run(device, log_format),
            Self::CreatePrimary(args) => args.run(device, log_format),
            Self::Delete(args) => args.run(device, log_format),
            Self::Import(args) => args.run(device, log_format),
            Self::Load(args) => args.run(device, log_format),
            Self::Objects(args) => args.run(device, log_format),
            Self::PcrEvent(args) => args.run(device, log_format),
            Self::PcrRead(args) => args.run(device, log_format),
            Self::Policy(args) => args.run(device, log_format),
            Self::PrintError(args) => args.run(device, log_format),
            Self::ResetLock(args) => args.run(device, log_format),
            Self::Save(args) => args.run(device, log_format),
            Self::Seal(args) => args.run(device, log_format),
            Self::StartSession(args) => args.run(device, log_format),
            Self::Unseal(args) => args.run(device, log_format),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuthArgs {
    pub auth: Option<String>,
}

#[derive(Debug, Default)]
pub struct CreatePrimary {
    pub hierarchy: Hierarchy,
    pub alg: Alg,
    pub persistent: Option<TpmPersistent>,
    pub auth: AuthArgs,
}

#[derive(Debug, Default)]
pub struct Save {
    pub object_handle: u32,
    pub persistent_handle: TpmPersistent,
    pub auth: AuthArgs,
}

#[derive(Debug, Default)]
pub struct Delete {
    pub handle: u32,
    pub auth: AuthArgs,
}

#[derive(Debug, Default)]
pub struct Import {
    pub parent_auth: AuthArgs,
}

#[derive(Debug, Default)]
pub struct Algorithms {
    pub filter: Option<String>,
}

#[derive(Debug, Default)]
pub struct Load {
    pub parent_auth: AuthArgs,
}

#[derive(Debug, Default)]
pub struct Objects {}

#[derive(Debug, Default)]
pub struct PcrRead {
    pub selection: String,
}

#[derive(Debug, Default)]
pub struct PcrEvent {
    pub pcr_handle: u32,
    pub data: String,
    pub auth: AuthArgs,
}

#[derive(Debug)]
pub struct PrintError {
    pub rc: TpmRc,
}

#[derive(Debug, Default)]
pub struct ResetLock {
    pub auth: AuthArgs,
}

#[derive(Debug, Default)]
pub struct StartSession {
    pub session_type: SessionType,
    pub hash_alg: SessionHashAlg,
}

#[derive(Debug, Default)]
pub struct Seal {
    pub parent_auth: AuthArgs,
    pub object_auth: AuthArgs,
}

#[derive(Debug, Default)]
pub struct Unseal {
    pub auth: AuthArgs,
}

#[derive(Debug, Default)]
pub struct Convert {
    pub from: KeyFormat,
    pub to: KeyFormat,
}

#[derive(Debug, Default)]
pub struct Policy {
    pub expression: String,
    pub auth: AuthArgs,
    pub partial: bool,
}

/// Retrieves all handles of a specific type from the TPM.
///
/// # Errors
///
/// Returns a `TpmError` if the `get_capability` call to the TPM device fails.
pub fn get_handles(
    device: &mut crate::TpmDevice,
    handle: TpmRh,
    log_format: LogFormat,
) -> Result<Vec<u32>, TpmError> {
    let cap_data_vec = device.get_capability(
        TpmCap::Handles,
        handle as u32,
        crate::TPM_CAP_PROPERTY_MAX,
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
