// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, Import, Object},
    create_import_blob, get_auth_sessions, read_public,
    util::{build_to_vec, consume_and_get_parent_handle},
    Command, CommandIo, Envelope, ObjectData, PrivateKey, TpmDevice, TpmError, ID_IMPORTABLE_KEY,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use log::warn;
use std::io;
use tpm2_protocol::data::{Tpm2bPublic, TpmAlgId, TpmtSymDef, TpmuSymKeyBits, TpmuSymMode};
use tpm2_protocol::message::{TpmFlushContextCommand, TpmImportCommand};

const ABOUT: &str = "Imports an external key";
const USAGE: &str = "tpm2sh import [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--auth",
        "<AUTH>",
        "Authorization for the parent object",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Import {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("import", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Import::default();
        while let Some(arg) = parser.next()? {
            match arg {
                Long("auth") => args.parent_auth.auth = Some(parser.value()?.string()?),
                Short('h') | Long("help") => {
                    Self::help();
                    return Err(TpmError::HelpDisplayed);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }
        Ok(Commands::Import(args))
    }

    /// Runs `import`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError`.
    #[allow(clippy::too_many_lines)]
    fn run(&self, chip: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError> {
        let mut io = CommandIo::new(io::stdout(), log_format)?;
        let session = io.take_session()?;

        let (parent_handle, needs_flush) =
            consume_and_get_parent_handle(&mut io, chip, log_format)?;

        let result = (|| {
            let (parent_public, parent_name) = read_public(chip, parent_handle, log_format)?;
            let parent_name_alg = parent_public.name_alg;

            let private_key_obj = io.consume_object(|obj| {
                let cli::Object::TpmObject(s) = obj;
                !s.starts_with("0x")
            })?;
            let cli::Object::TpmObject(private_key_path) = private_key_obj;

            let private_key = PrivateKey::from_pem_file(private_key_path.as_ref())?;
            let public = private_key.to_tpmt_public(parent_name_alg)?;
            let public_bytes = Tpm2bPublic {
                inner: public.clone(),
            };
            let private_bytes = private_key.get_private_blob()?;

            let (duplicate, in_sym_seed, encryption_key) = create_import_blob(
                &parent_public,
                public.object_type,
                private_bytes,
                &parent_name,
            )?;

            let import_cmd = TpmImportCommand {
                encryption_key,
                object_public: public_bytes,
                duplicate,
                in_sym_seed,
                symmetric_alg: TpmtSymDef {
                    algorithm: TpmAlgId::Aes,
                    key_bits: TpmuSymKeyBits::Aes(128),
                    mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
                },
            };

            let handles = [parent_handle.into()];
            let sessions = get_auth_sessions(
                &import_cmd,
                &handles,
                session.as_ref(),
                self.parent_auth.auth.as_deref(),
            )?;

            let (resp, _) = chip.execute(&import_cmd, Some(&handles), &sessions, log_format)?;
            let import_resp = resp.Import().map_err(|e| {
                TpmError::Execution(format!("unexpected response type for Import: {e:?}"))
            })?;

            let pub_key_bytes = build_to_vec(&Tpm2bPublic { inner: public })?;
            let priv_key_bytes = build_to_vec(&import_resp.out_private)?;

            let data = ObjectData {
                oid: ID_IMPORTABLE_KEY.to_string(),
                empty_auth: false,
                parent: format!("{parent_handle:#010x}"),
                public: base64_engine.encode(pub_key_bytes),
                private: base64_engine.encode(priv_key_bytes),
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
