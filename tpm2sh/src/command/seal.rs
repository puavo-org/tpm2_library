// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, Object, Seal},
    get_auth_sessions, input_to_bytes,
    util::{build_to_vec, consume_and_get_parent_handle},
    Command, CommandIo, Envelope, ObjectData, TpmDevice, TpmError, ID_SEALED_DATA,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use log::warn;
use std::io::{self, IsTerminal};
use tpm2_protocol::{
    data::{
        Tpm2b, Tpm2bAuth, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmaObject, TpmlPcrSelection, TpmsKeyedhashParms, TpmsSensitiveCreate,
        TpmtPublic, TpmtScheme, TpmuPublicId, TpmuPublicParms,
    },
    message::{TpmCreateCommand, TpmFlushContextCommand},
};

const ABOUT: &str = "Seals a keyedhash object";
const USAGE: &str = "tpm2sh seal [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--parent-auth",
        "<AUTH>",
        "Authorization for the parent object",
    ),
    (
        None,
        "--object-auth",
        "<AUTH>",
        "Authorization for the new sealed object",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Seal {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("seal", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Seal::default();
        while let Some(arg) = parser.next()? {
            match arg {
                Long("parent-auth") => args.parent_auth.auth = Some(parser.value()?.string()?),
                Long("object-auth") => args.object_auth.auth = Some(parser.value()?.string()?),
                Short('h') | Long("help") => {
                    Self::help();
                    return Err(TpmError::HelpDisplayed);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }
        Ok(Commands::Seal(args))
    }

    /// Runs `seal`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError> {
        if std::io::stdin().is_terminal() {
            Self::help();
            std::process::exit(1);
        }

        let mut io = CommandIo::new(io::stdout(), log_format)?;
        let session = io.take_session()?;

        let (parent_handle, needs_flush) =
            consume_and_get_parent_handle(&mut io, chip, log_format)?;

        let result = (|| {
            let data_to_seal_obj = io.consume_object(|_| true)?;
            let Object::TpmObject(data_str) = data_to_seal_obj;
            let data_to_seal = input_to_bytes(&data_str)?;

            let mut object_attributes = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT;
            if self.object_auth.auth.is_some() {
                object_attributes |= TpmaObject::USER_WITH_AUTH;
            }
            let public_template = TpmtPublic {
                object_type: TpmAlgId::KeyedHash,
                name_alg: TpmAlgId::Sha256,
                object_attributes,
                auth_policy: Tpm2bDigest::default(),
                parameters: TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                    scheme: TpmtScheme {
                        scheme: TpmAlgId::Null,
                    },
                }),
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
            let sessions = get_auth_sessions(
                &cmd,
                &handles,
                session.as_ref(),
                self.parent_auth.auth.as_deref(),
            )?;

            let (resp, _) = chip.execute(&cmd, Some(&handles), &sessions, log_format)?;

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

            let new_object = Object::TpmObject(
                Envelope {
                    version: 1,
                    object_type: "object".to_string(),
                    data: data.to_json(),
                }
                .to_json()
                .dump(),
            );

            io.push_object(new_object);
            io.finalize()
        })();

        if needs_flush {
            let flush_cmd = TpmFlushContextCommand {
                flush_handle: parent_handle.into(),
            };
            if let Err(flush_err) = chip.execute(&flush_cmd, Some(&[]), &[], log_format) {
                warn!(
                    "Failed to flush transient parent handle {parent_handle:#010x} after operation: {flush_err}"
                );
                if result.is_ok() {
                    return Err(flush_err);
                }
            }
        }
        result
    }
}
