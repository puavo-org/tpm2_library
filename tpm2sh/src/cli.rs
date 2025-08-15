// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{formats::PcrOutput, Alg, Command, TpmError};
use serde::{
    de::{self, Deserializer, MapAccess, Visitor},
    ser::{SerializeMap, Serializer},
    Deserialize, Serialize,
};
use std::fmt;
use std::str::FromStr;
use tpm2_protocol::{
    data::{TpmCap, TpmRc, TpmRh, TpmuCapabilities},
    TpmPersistent, TpmTransient,
};

#[derive(Debug, Clone)]
pub enum Object {
    Handle(TpmTransient),
    Persistent(TpmPersistent),
    Context(serde_json::Value),
    Pcrs(PcrOutput),
}

impl Serialize for Object {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Object::Handle(h) => {
                map.serialize_entry("handle", &format!("{:#010x}", u32::from(*h)))?;
            }
            Object::Persistent(p) => {
                map.serialize_entry("persistent", &format!("{:#010x}", u32::from(*p)))?;
            }
            Object::Context(c) => {
                map.serialize_entry("context", c)?;
            }
            Object::Pcrs(p) => {
                map.serialize_entry("pcrs", p)?;
            }
        }
        map.end()
    }
}

struct ObjectVisitor;

impl<'de> Visitor<'de> for ObjectVisitor {
    type Value = Object;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .write_str("an object with a single key: 'handle', 'persistent', 'context', or 'pcrs'")
    }

    fn visit_map<V>(self, mut map: V) -> Result<Object, V::Error>
    where
        V: MapAccess<'de>,
    {
        let (key, value): (String, serde_json::Value) = map
            .next_entry()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;

        match key.as_str() {
            "handle" => {
                let s: String = serde_json::from_value(value).map_err(de::Error::custom)?;
                let handle = crate::parse_hex_u32(&s)
                    .map(TpmTransient)
                    .map_err(de::Error::custom)?;
                Ok(Object::Handle(handle))
            }
            "persistent" => {
                let s: String = serde_json::from_value(value).map_err(de::Error::custom)?;
                let handle = crate::parse_persistent_handle(&s).map_err(de::Error::custom)?;
                Ok(Object::Persistent(handle))
            }
            "context" => Ok(Object::Context(value)),
            "pcrs" => {
                let pcrs = serde_json::from_value(value).map_err(de::Error::custom)?;
                Ok(Object::Pcrs(pcrs))
            }
            _ => Err(de::Error::unknown_field(
                &key,
                &["handle", "persistent", "context", "pcrs"],
            )),
        }
    }
}

impl<'de> Deserialize<'de> for Object {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ObjectVisitor)
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
    pub session: Option<String>,
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
    fn run(
        &self,
        device: &mut crate::TpmDevice,
        session: Option<&crate::AuthSession>,
        log_format: crate::cli::LogFormat,
    ) -> Result<(), crate::TpmError> {
        match self {
            Self::Algorithms(args) => args.run(device, session, log_format),
            Self::Convert(args) => args.run(device, session, log_format),
            Self::CreatePrimary(args) => args.run(device, session, log_format),
            Self::Delete(args) => args.run(device, session, log_format),
            Self::Import(args) => args.run(device, session, log_format),
            Self::Load(args) => args.run(device, session, log_format),
            Self::Objects(args) => args.run(device, session, log_format),
            Self::PcrEvent(args) => args.run(device, session, log_format),
            Self::PcrRead(args) => args.run(device, session, log_format),
            Self::Policy(args) => args.run(device, session, log_format),
            Self::PrintError(args) => args.run(device, session, log_format),
            Self::ResetLock(args) => args.run(device, session, log_format),
            Self::Save(args) => args.run(device, session, log_format),
            Self::Seal(args) => args.run(device, session, log_format),
            Self::StartSession(args) => args.run(device, session, log_format),
            Self::Unseal(args) => args.run(device, session, log_format),
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
