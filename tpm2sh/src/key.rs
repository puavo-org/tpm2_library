// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli, get_auth_sessions, session::AuthSession, TpmDevice, TpmError};
use log::debug;
use std::{cmp::Ordering, str::FromStr};
use tpm2_protocol::{
    data::{self, TpmAlgId, TpmEccCurve, TpmtPublic},
    message::{TpmFlushContextCommand, TpmLoadCommand, TpmReadPublicCommand},
    TpmTransient,
};

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

impl Default for Alg {
    fn default() -> Self {
        Self {
            name: String::new(),
            object_type: TpmAlgId::Null,
            name_alg: TpmAlgId::Null,
            params: AlgInfo::KeyedHash,
        }
    }
}

impl FromStr for Alg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.as_slice() {
            ["rsa", key_bits_str, name_alg_str] => {
                let key_bits: u16 = key_bits_str
                    .parse()
                    .map_err(|_| format!("invalid RSA key bits value: '{key_bits_str}'"))?;
                let name_alg = crate::key::tpm_alg_id_from_str(name_alg_str)?;
                Ok(Self {
                    name: s.to_string(),
                    object_type: TpmAlgId::Rsa,
                    name_alg,
                    params: AlgInfo::Rsa { key_bits },
                })
            }
            ["ecc", curve_id_str, name_alg_str] => {
                let curve_id = crate::key::tpm_ecc_curve_from_str(curve_id_str)?;
                let name_alg = crate::key::tpm_alg_id_from_str(name_alg_str)?;
                Ok(Self {
                    name: s.to_string(),
                    object_type: TpmAlgId::Ecc,
                    name_alg,
                    params: AlgInfo::Ecc { curve_id },
                })
            }
            ["keyedhash", name_alg_str] => {
                let name_alg = crate::key::tpm_alg_id_from_str(name_alg_str)?;
                Ok(Self {
                    name: s.to_string(),
                    object_type: TpmAlgId::KeyedHash,
                    name_alg,
                    params: AlgInfo::KeyedHash,
                })
            }
            _ => Err(format!("invalid algorithm format: '{s}'")),
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

/// Reads the public area and name of a TPM object.
///
/// # Errors
///
/// Returns `TpmError` if the `ReadPublic` command fails.
pub fn read_public(
    chip: &mut TpmDevice,
    handle: TpmTransient,
    log_format: cli::LogFormat,
) -> Result<(TpmtPublic, data::Tpm2bName), TpmError> {
    let cmd = TpmReadPublicCommand {
        object_handle: handle.0.into(),
    };
    let (resp, _) = chip.execute(&cmd, &[], log_format)?;
    let read_public_resp = resp
        .ReadPublic()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    Ok((read_public_resp.out_public.inner, read_public_resp.name))
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
#[allow(clippy::too_many_arguments)]
pub fn with_loaded_object<F, R>(
    chip: &mut TpmDevice,
    parent_handle: TpmTransient,
    parent_auth: &cli::AuthArgs,
    session: Option<&AuthSession>,
    in_public: data::Tpm2bPublic,
    in_private: data::Tpm2bPrivate,
    log_format: cli::LogFormat,
    op: F,
) -> Result<R, TpmError>
where
    F: FnOnce(&mut TpmDevice, TpmTransient) -> Result<R, TpmError>,
{
    let load_cmd = TpmLoadCommand {
        parent_handle: parent_handle.0.into(),
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
    let (load_resp, _) = chip.execute(&load_cmd, &parent_sessions, log_format)?;
    let load_resp = load_resp
        .Load()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    let object_handle = load_resp.object_handle;

    let op_result = op(chip, object_handle);

    let flush_cmd = TpmFlushContextCommand {
        flush_handle: object_handle.into(),
    };
    let flush_err = chip.execute(&flush_cmd, &[], log_format).err();

    if let Some(e) = flush_err {
        debug!(
            target: "cli::device",
            "failed to flush object context after operation: handle = {object_handle:?}, error = {e}"
        );
        if op_result.is_ok() {
            return Err(e);
        }
    }

    op_result
}
