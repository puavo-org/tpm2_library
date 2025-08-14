// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{formats::PcrOutput, Alg, Command, TpmError};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{
    de::{self, Deserializer, MapAccess, Visitor},
    ser::{SerializeMap, Serializer},
    Deserialize, Serialize,
};
use std::fmt;
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

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "TPM 2.0 command-line interface",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[arg(short, long, default_value = r"/dev/tpmrm0", global = true)]
    pub device: String,
    /// Authorization session context
    #[arg(long, global = true)]
    pub session: Option<String>,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(ValueEnum, Copy, Clone, Debug)]
pub enum Hierarchy {
    Owner,
    Platform,
    Endorsement,
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

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionType {
    Hmac,
    Policy,
    Trial,
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

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum SessionHashAlg {
    Sha256,
    Sha384,
    Sha512,
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

#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyFormat {
    #[default]
    Json,
    Pem,
    Der,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Lists avaible algorithms
    Algorithms(Algorithms),
    /// Converts keys between ASN.1 and JSON format
    Convert(Convert),
    /// Creates a primary key
    CreatePrimary(CreatePrimary),
    /// Deletes a transient or persistent object
    Delete(Delete),
    /// Imports an external key
    Import(Import),
    /// Loads a TPM key
    Load(Load),
    /// Lists objects in volatile and non-volatile memory
    Objects(Objects),
    /// Extends a PCR with an event
    PcrEvent(PcrEvent),
    /// Reads PCRs
    PcrRead(PcrRead),
    /// Builds a policy using a policy expression
    Policy(Policy),
    /// Encodes and print a TPM error code
    PrintError(PrintError),
    /// Resets the dictionary attack lockout timer
    ResetLock(ResetLock),
    /// Saves to non-volatile memory
    Save(Save),
    /// Seals a keyedhash object
    Seal(Seal),
    /// Starts an authorization session
    StartSession(StartSession),
    /// Unseals a keyedhash object
    Unseal(Unseal),
}

impl Command for Commands {
    fn run(
        &self,
        device: &mut crate::TpmDevice,
        session: Option<&crate::AuthSession>,
    ) -> Result<(), crate::TpmError> {
        match self {
            Self::Algorithms(args) => args.run(device, session),
            Self::Convert(args) => args.run(device, session),
            Self::CreatePrimary(args) => args.run(device, session),
            Self::Delete(args) => args.run(device, session),
            Self::Import(args) => args.run(device, session),
            Self::Load(args) => args.run(device, session),
            Self::Objects(args) => args.run(device, session),
            Self::PcrEvent(args) => args.run(device, session),
            Self::PcrRead(args) => args.run(device, session),
            Self::Policy(args) => args.run(device, session),
            Self::PrintError(args) => args.run(device, session),
            Self::ResetLock(args) => args.run(device, session),
            Self::Save(args) => args.run(device, session),
            Self::Seal(args) => args.run(device, session),
            Self::StartSession(args) => args.run(device, session),
            Self::Unseal(args) => args.run(device, session),
        }
    }
}

/// Arguments for authorization
#[derive(Args, Debug, Clone)]
pub struct AuthArgs {
    /// Authorization value
    #[arg(long)]
    pub auth: Option<String>,
}

#[derive(Args, Debug)]
pub struct CreatePrimary {
    /// Hierarchy
    #[arg(short = 'H', long, value_enum)]
    pub hierarchy: Hierarchy,
    /// Public key algorithm. Run 'list-algs' for options
    #[arg(long, value_parser = |s: &str| Alg::try_from(s).map_err(|e| e.to_string()))]
    pub alg: Alg,
    /// Store object to non-volatile memory
    #[arg(long, value_parser = crate::parse_persistent_handle)]
    pub persistent: Option<TpmPersistent>,
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct Save {
    /// Handle of the transient object
    #[arg(long, value_parser = crate::parse_hex_u32)]
    pub object_handle: u32,
    /// Handle for the persistent object to be created
    #[arg(long, value_parser = crate::parse_persistent_handle)]
    pub persistent_handle: TpmPersistent,
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct Delete {
    /// Handle of the object to delete (transient or persistent)
    #[arg(value_parser = crate::parse_hex_u32)]
    pub handle: u32,
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct Import {
    #[command(flatten)]
    pub parent_auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct Algorithms {
    /// A regex to filter the algorithm names
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Args, Debug)]
pub struct Load {
    #[command(flatten)]
    pub parent_auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct Objects {}

#[derive(Args, Debug)]
pub struct PcrRead {
    /// A PCR selection string (e.g., "sha1:0,1,2+sha256:0,1,2").
    pub selection: String,
}

#[derive(Args, Debug)]
pub struct PcrEvent {
    /// The handle of the PCR to extend.
    #[arg(long, value_parser = crate::parse_hex_u32)]
    pub pcr_handle: u32,
    /// The data to be hashed and extended into the PCR.
    pub data: String,
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct PrintError {
    /// TPM error code
    #[arg(value_parser = crate::parse_tpm_rc)]
    pub rc: TpmRc,
}

#[derive(Args, Debug)]
pub struct ResetLock {
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct StartSession {
    /// Session type
    #[arg(long, value_enum, default_value_t = SessionType::Hmac)]
    pub session_type: SessionType,
    /// Hash algorithm for the session
    #[arg(long, value_enum, default_value_t = SessionHashAlg::Sha256)]
    pub hash_alg: SessionHashAlg,
}

#[derive(Args, Debug)]
pub struct Seal {
    #[command(flatten)]
    pub parent_auth: AuthArgs,
    #[command(flatten)]
    pub object_auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct Unseal {
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct Convert {
    /// Input format
    #[arg(long, value_enum, default_value_t = KeyFormat::Json)]
    pub from: KeyFormat,
    /// Output format
    #[arg(long, value_enum, default_value_t = KeyFormat::Pem)]
    pub to: KeyFormat,
}

#[derive(Args, Debug)]
pub struct Policy {
    /// A policy expression string (e.g. 'pcr(sha256:0,"...")')
    pub expression: String,
    #[command(flatten)]
    pub auth: AuthArgs,
}

/// Retrieves all handles of a specific type from the TPM.
///
/// # Errors
///
/// Returns a `TpmError` if the `get_capability` call to the TPM device fails.
pub fn get_handles(device: &mut crate::TpmDevice, handle: TpmRh) -> Result<Vec<u32>, TpmError> {
    let cap_data_vec =
        device.get_capability(TpmCap::Handles, handle as u32, crate::TPM_CAP_PROPERTY_MAX)?;
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
