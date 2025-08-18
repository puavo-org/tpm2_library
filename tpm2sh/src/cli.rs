// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{Alg, Command, TpmError};
use std::str::FromStr;
use tpm2_protocol::{
    data::{TpmRc, TpmRh},
    TpmPersistent,
};

#[derive(Debug, Clone)]
pub enum Object {
    TpmObject(String),
}

impl Object {
    #[must_use]
    pub fn to_json(&self) -> json::JsonValue {
        match self {
            Object::TpmObject(s) => json::object! { "tpm-object": s.clone() },
        }
    }

    /// Deserializes an `Object` from a `json::JsonValue`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::Parse` if the JSON object is malformed.
    pub fn from_json(value: &json::JsonValue) -> Result<Self, TpmError> {
        if !value.is_object() {
            return Err(TpmError::Parse("expected a JSON object".to_string()));
        }

        let hex_string = value["tpm-object"]
            .as_str()
            .ok_or_else(|| TpmError::Parse("missing or invalid 'tpm-object' key".to_string()))?;

        Ok(Object::TpmObject(hex_string.to_string()))
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
    pub handle: String,
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
}

/// Retrieves all handles of a specific type from the TPM.
///
/// # Errors
///
/// Returns a `TpmError` if the `get_capability` call to the TPM device fails.
pub fn get_handles(
    device: &mut crate::TpmDevice,
    handle_type: TpmRh,
    log_format: LogFormat,
) -> Result<Vec<u32>, TpmError> {
    device.get_all_handles(handle_type, log_format)
}
