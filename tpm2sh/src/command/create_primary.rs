// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    build_to_vec, cli, get_auth_sessions, Alg, AlgInfo, AuthSession, Command, ContextData,
    Envelope, TpmDevice, TpmError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use tpm2_protocol::{
    data::{
        Tpm2b, Tpm2bAuth, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmRh, TpmaObject, TpmlPcrSelection, TpmsEccPoint, TpmsKeyedhashParms,
        TpmsSensitiveCreate, TpmtKdfScheme, TpmtPublic, TpmtScheme, TpmtSymDefObject, TpmuPublicId,
        TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{TpmContextSaveCommand, TpmCreatePrimaryCommand, TpmEvictControlCommand},
    TpmBuffer, TpmTransient,
};

fn build_public_template(alg_desc: &Alg) -> TpmtPublic {
    let mut object_attributes = TpmaObject::USER_WITH_AUTH
        | TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN;

    let (parameters, unique) = match alg_desc.params {
        AlgInfo::Rsa { key_bits } => {
            object_attributes |= TpmaObject::DECRYPT | TpmaObject::RESTRICTED;
            (
                TpmuPublicParms::Rsa {
                    symmetric: TpmtSymDefObject {
                        algorithm: TpmAlgId::Aes,
                        key_bits: TpmuSymKeyBits::Aes(128),
                        mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
                    },
                    scheme: TpmtScheme::default(),
                    key_bits,
                    exponent: 0,
                },
                TpmuPublicId::Rsa(TpmBuffer::default()),
            )
        }
        AlgInfo::Ecc { curve_id } => {
            object_attributes |= TpmaObject::DECRYPT | TpmaObject::RESTRICTED;
            (
                TpmuPublicParms::Ecc {
                    symmetric: TpmtSymDefObject {
                        algorithm: TpmAlgId::Aes,
                        key_bits: TpmuSymKeyBits::Aes(128),
                        mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
                    },
                    scheme: TpmtScheme::default(),
                    curve_id,
                    kdf: TpmtKdfScheme::default(),
                },
                TpmuPublicId::Ecc(TpmsEccPoint::default()),
            )
        }
        AlgInfo::KeyedHash => (
            TpmuPublicParms::KeyedHash {
                details: TpmsKeyedhashParms {
                    scheme: TpmtScheme {
                        scheme: TpmAlgId::Null,
                    },
                },
            },
            TpmuPublicId::KeyedHash(TpmBuffer::default()),
        ),
    };

    TpmtPublic {
        object_type: alg_desc.object_type,
        name_alg: alg_desc.name_alg,
        object_attributes,
        auth_policy: Tpm2bDigest::default(),
        parameters,
        unique,
    }
}

/// Saves a transient key's context to a JSON string.
///
/// # Errors
///
/// Returns a `TpmError` if the context cannot be saved or the file cannot be
/// written.
pub fn save_key_context(
    chip: &mut TpmDevice,
    handle: TpmTransient,
    log_format: cli::LogFormat,
) -> Result<String, TpmError> {
    let save_command = TpmContextSaveCommand {};
    let (resp, _) = chip.execute(&save_command, Some(&[handle.into()]), &[], log_format)?;

    let save_resp = resp
        .ContextSave()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

    let context_bytes = build_to_vec(&save_resp.context)?;

    let data = ContextData {
        context_blob: base64_engine.encode(context_bytes),
    };
    let envelope = Envelope {
        version: 1,
        object_type: "context".to_string(),
        data: serde_json::to_value(data).map_err(|e| TpmError::Json(e.to_string()))?,
    };
    serde_json::to_string_pretty(&envelope).map_err(|e| TpmError::Json(e.to_string()))
}

impl Command for crate::cli::CreatePrimary {
    /// Runs `create-primary`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(
        &self,
        chip: &mut TpmDevice,
        session: Option<&AuthSession>,
        log_format: cli::LogFormat,
    ) -> Result<(), TpmError> {
        let primary_handle: TpmRh = self.hierarchy.into();
        let handles = [primary_handle as u32];
        let public_template = build_public_template(&self.alg);
        let user_auth = self.auth.auth.as_deref().unwrap_or("").as_bytes();

        let cmd = TpmCreatePrimaryCommand {
            in_sensitive: Tpm2bSensitiveCreate {
                inner: TpmsSensitiveCreate {
                    user_auth: Tpm2bAuth::try_from(user_auth)?,
                    data: Tpm2bSensitiveData::default(),
                },
            },
            in_public: Tpm2bPublic {
                inner: public_template,
            },
            outside_info: Tpm2b::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };

        let sessions = get_auth_sessions(&cmd, &handles, session, self.auth.auth.as_deref())?;
        let (resp, _) = chip.execute(&cmd, Some(&handles), &sessions, log_format)?;

        let create_primary_resp = resp
            .CreatePrimary()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
        let object_handle = create_primary_resp.object_handle;

        if let Some(persistent_handle) = self.persistent {
            let evict_cmd = TpmEvictControlCommand { persistent_handle };
            let evict_handles = [TpmRh::Owner as u32, object_handle.into()];
            let evict_sessions = get_auth_sessions(&evict_cmd, &evict_handles, session, None)?;
            let (resp, _) = chip.execute(
                &evict_cmd,
                Some(&evict_handles),
                &evict_sessions,
                log_format,
            )?;
            resp.EvictControl()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
            println!("{persistent_handle:#010x}");
        } else {
            let json_out = save_key_context(chip, object_handle, log_format)?;
            println!("{json_out}");
        }

        Ok(())
    }
}
