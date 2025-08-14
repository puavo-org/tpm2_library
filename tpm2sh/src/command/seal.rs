// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    build_to_vec,
    cli::{Object, Seal},
    get_auth_sessions, input_to_bytes, object_to_handle, AuthSession, Command, CommandIo, Envelope,
    ObjectData, TpmDevice, TpmError, ID_SEALED_DATA,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::io;
use tpm2_protocol::{
    data::{
        Tpm2b, Tpm2bAuth, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmaObject, TpmlPcrSelection, TpmsKeyedhashParms, TpmsSensitiveCreate,
        TpmtPublic, TpmtScheme, TpmuPublicId, TpmuPublicParms,
    },
    message::TpmCreateCommand,
};

impl Command for Seal {
    /// Runs `seal`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, session: Option<&AuthSession>) -> Result<(), TpmError> {
        let mut io = CommandIo::new(io::stdin(), io::stdout(), session)?;

        let parent_obj = io.consume_object(|obj| !matches!(obj, Object::Context(_)))?;
        let parent_handle = object_to_handle(chip, &parent_obj)?;

        let data_to_seal_obj = io.consume_object(|obj| matches!(obj, Object::Context(_)))?;
        let data_to_seal = match data_to_seal_obj {
            Object::Context(v) => {
                let s = v.as_str().ok_or_else(|| {
                    TpmError::Parse("context for sealed data must be a string".to_string())
                })?;
                input_to_bytes(s)?
            }
            _ => unreachable!(),
        };

        let mut object_attributes = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT;
        if self.object_auth.auth.is_some() {
            object_attributes |= TpmaObject::USER_WITH_AUTH;
        }
        let public_template = TpmtPublic {
            object_type: TpmAlgId::KeyedHash,
            name_alg: TpmAlgId::Sha256,
            object_attributes,
            auth_policy: Tpm2bDigest::default(),
            parameters: TpmuPublicParms::KeyedHash {
                details: TpmsKeyedhashParms {
                    scheme: TpmtScheme {
                        scheme: TpmAlgId::Null,
                    },
                },
            },
            unique: TpmuPublicId::KeyedHash(tpm2_protocol::TpmBuffer::default()),
        };

        let sealed_obj_auth = self.object_auth.auth.as_deref().unwrap_or("").as_bytes();
        let cmd = TpmCreateCommand {
            in_sensitive: Tpm2bSensitiveCreate {
                inner: TpmsSensitiveCreate {
                    user_auth: Tpm2bAuth::try_from(sealed_obj_auth)?,
                    data: Tpm2bSensitiveData::try_from(data_to_seal.as_slice())?,
                },
            },
            in_public: Tpm2bPublic {
                inner: public_template,
            },
            outside_info: Tpm2b::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };

        let handles = [parent_handle.into()];
        let sessions =
            get_auth_sessions(&cmd, &handles, io.session, self.parent_auth.auth.as_deref())?;

        let (resp, _) = chip.execute(&cmd, Some(&handles), &sessions)?;

        let create_resp = resp.Create().map_err(|e| {
            TpmError::Execution(format!("unexpected response type for Create: {e:?}"))
        })?;

        let pub_bytes = build_to_vec(&create_resp.out_public)?;
        let priv_bytes = build_to_vec(&create_resp.out_private)?;

        let data = ObjectData {
            oid: ID_SEALED_DATA.to_string(),
            empty_auth: sealed_obj_auth.is_empty(),
            parent: format!("{parent_handle:#010x}"),
            public: base64_engine.encode(pub_bytes),
            private: base64_engine.encode(priv_bytes),
        };

        let new_object = Object::Context(serde_json::to_value(Envelope {
            version: 1,
            object_type: "object".to_string(),
            data: serde_json::to_value(data)?,
        })?);

        io.push_object(new_object);
        io.finalize()
    }
}
