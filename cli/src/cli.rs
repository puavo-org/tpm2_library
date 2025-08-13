// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{Alg, TpmError};
use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_num::maybe_hex;
use serde::{
    de::{self, Deserializer, Visitor},
    Serialize, Serializer,
};
use tpm2_protocol::{
    data::{TpmCap, TpmRc, TpmRh, TpmuCapabilities},
    TpmPersistent, TpmTransient,
};

fn parse_hex_u32(s: &str) -> Result<u32, TpmError> {
    maybe_hex(s).map_err(|e| TpmError::InvalidHandle(e.to_string()))
}

fn parse_persistent_handle(s: &str) -> Result<TpmPersistent, TpmError> {
    parse_hex_u32(s).map(TpmPersistent)
}

fn parse_tpm_rc(s: &str) -> Result<TpmRc, TpmError> {
    let raw_rc: u32 = maybe_hex(s).map_err(|e| TpmError::Execution(e.to_string()))?;
    Ok(TpmRc::try_from(raw_rc)?)
}

#[derive(Debug, Clone)]
pub enum Object {
    Handle(TpmTransient),
    Persistent(TpmPersistent),
    Context(String),
}

impl Serialize for Object {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self {
            Object::Handle(handle) => format!("handle:{:#010x}", u32::from(*handle)),
            Object::Persistent(handle) => format!("persistent:{:#010x}", u32::from(*handle)),
            Object::Context(s) => format!("context:{s}"),
        };
        serializer.serialize_str(&s)
    }
}

impl<'de> de::Deserialize<'de> for Object {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ObjectVisitor;

        impl Visitor<'_> for ObjectVisitor {
            type Value = Object;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string with format 'prefix:value'")
            }

            fn visit_str<E>(self, value: &str) -> Result<Object, E>
            where
                E: de::Error,
            {
                let parts: Vec<&str> = value.splitn(2, ':').collect();
                if parts.len() != 2 {
                    return Err(E::custom(format!(
                        "invalid object format, expected 'prefix:value', got '{value}'"
                    )));
                }
                let prefix = parts[0];
                let val_str = parts[1];

                match prefix {
                    "handle" => {
                        let handle = parse_hex_u32(val_str).map(TpmTransient).map_err(|e| {
                            E::custom(format!("invalid handle value '{val_str}': {e}"))
                        })?;
                        Ok(Object::Handle(handle))
                    }
                    "persistent" => {
                        let handle = parse_persistent_handle(val_str).map_err(|e| {
                            E::custom(format!("invalid persistent handle value '{val_str}': {e}"))
                        })?;
                        Ok(Object::Persistent(handle))
                    }
                    "context" => Ok(Object::Context(val_str.to_string())),
                    _ => Err(E::custom(format!("unknown object prefix '{prefix}'"))),
                }
            }
        }

        deserializer.deserialize_str(ObjectVisitor)
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
    #[arg(short, long, default_value = r"/dev/tpmrm0")]
    pub device: String,
    /// Authorization session context
    #[arg(long)]
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

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum SessionType {
    Hmac,
    Policy,
    Trial,
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
    Convert(ConvertArgs),
    /// Creates a primary key
    CreatePrimary(CreatePrimaryArgs),
    /// Deletes a transient or persistent object
    Delete(DeleteArgs),
    /// Imports an external key
    Import(ImportArgs),
    /// Loads a TPM key
    Load(LoadArgs),
    /// Lists objects in volatile and non-volatile memory
    Objects,
    /// Extends a PCR with an event
    PcrEvent(PcrEventArgs),
    /// Reads PCRs
    PcrRead(PcrReadArgs),
    /// Constrain a policy with an authorization value
    PolicySecret(PolicySecretArgs),
    /// Constrain a policy to a specific PCR state
    PolicyPcr(PolicyPcrArgs),
    /// Combine policies to  a union policy
    PolicyOr(PolicyOrArgs),
    /// Encodes and print a TPM error code
    PrintError(PrintErrorArgs),
    /// Resets the dictionary attack lockout timer
    ResetLock(ResetLockArgs),
    /// Saves to non-volatile memory
    Save(SaveArgs),
    /// Seals a keyedhash object
    Seal(SealArgs),
    /// Starts an authorization session
    StartAuthSession(StartAuthSessionArgs),
    /// Unseals a keyedhash object
    Unseal(UnsealArgs),
}

/// Arguments for authorization
#[derive(Args, Debug, Clone)]
pub struct AuthArgs {
    /// Authorization value
    #[arg(long)]
    pub auth: Option<String>,
}

#[derive(Args, Debug)]
pub struct CreatePrimaryArgs {
    /// Hierarchy
    #[arg(short = 'H', long, value_enum)]
    pub hierarchy: Hierarchy,
    /// Public key algorithm. Run 'list-algs' for options
    #[arg(long, value_parser = |s: &str| Alg::try_from(s).map_err(|e| e.to_string()))]
    pub alg: Alg,
    /// Store object to non-volatile memory
    #[arg(long, value_parser = parse_persistent_handle)]
    pub persistent: Option<TpmPersistent>,
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct SaveArgs {
    /// Handle of the transient object
    #[arg(long, value_parser = parse_hex_u32)]
    pub object_handle: u32,
    /// Handle for the persistent object to be created
    #[arg(long, value_parser = parse_persistent_handle)]
    pub persistent_handle: TpmPersistent,
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Handle of the object to delete (transient or persistent)
    pub handle: String,
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
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
pub struct LoadArgs {
    #[command(flatten)]
    pub parent_auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct PcrReadArgs {
    /// A PCR selection string (e.g., "sha1:0,1,2+sha256:0,1,2").
    pub selection: String,
}

#[derive(Args, Debug)]
pub struct PcrEventArgs {
    /// The handle of the PCR to extend.
    #[arg(long, value_parser = parse_hex_u32)]
    pub pcr_handle: u32,
    /// The data to be hashed and extended into the PCR.
    pub data: String,
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct PrintErrorArgs {
    /// TPM error code
    #[arg(value_parser = parse_tpm_rc)]
    pub rc: TpmRc,
}

#[derive(Args, Debug)]
pub struct ResetLockArgs {
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct StartAuthSessionArgs {
    /// Session type
    #[arg(long, value_enum, default_value_t = SessionType::Hmac)]
    pub session_type: SessionType,
    /// Hash algorithm for the session
    #[arg(long, value_enum, default_value_t = SessionHashAlg::Sha256)]
    pub hash_alg: SessionHashAlg,
}

#[derive(Args, Debug)]
pub struct SealArgs {
    #[command(flatten)]
    pub parent_auth: AuthArgs,
    #[command(flatten)]
    pub object_auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct UnsealArgs {
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct ConvertArgs {
    /// Input format
    #[arg(long, value_enum, default_value_t = KeyFormat::Json)]
    pub from: KeyFormat,
    /// Output format
    #[arg(long, value_enum, default_value_t = KeyFormat::Pem)]
    pub to: KeyFormat,
}

#[derive(Args, Debug)]
pub struct PolicySecretArgs {
    /// Authorization handle
    #[arg(long, value_parser = parse_hex_u32)]
    pub auth_handle: u32,
    /// Expiration time in seconds. A negative value generates a ticket.
    #[arg(long, default_value_t = 0)]
    pub expiration: i32,
    #[command(flatten)]
    pub auth: AuthArgs,
}

#[derive(Args, Debug)]
pub struct PolicyPcrArgs {
    /// The PCR index to include in the policy
    #[arg(long)]
    pub pcr_index: u32,
    /// The expected digest of the PCR at the time of unsealing (hex)
    #[arg(long)]
    pub pcr_digest: String,
}

#[derive(Args, Debug)]
pub struct PolicyOrArgs {
    /// Path to a JSON session file for an OR branch
    #[arg(long = "branch", required = true)]
    pub branches: Vec<String>,
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
