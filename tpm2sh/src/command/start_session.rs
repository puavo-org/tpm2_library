// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, Object, StartSession},
    Command, Envelope, SessionData, TpmDevice, TpmError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use rand::{thread_rng, RngCore};
use tpm2_protocol::{
    data::{Tpm2b, TpmAlgId, TpmRh, TpmaSession, TpmtSymDefObject},
    message::TpmStartAuthSessionCommand,
};

const ABOUT: &str = "Starts an authorization session";
const USAGE: &str = "tpm2sh start-session [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--session-type",
        "<TYPE>",
        "[default: hmac, possible: hmac, policy, trial]",
    ),
    (
        None,
        "--hash-alg",
        "<ALG>",
        "[default: sha256, possible: sha256, sha384, sha512]",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for StartSession {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("start-session", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = StartSession::default();
        while let Some(arg) = parser.next()? {
            match arg {
                Long("session-type") => args.session_type = parser.value()?.string()?.parse()?,
                Long("hash-alg") => args.hash_alg = parser.value()?.string()?.parse()?,
                Short('h') | Long("help") => {
                    Self::help();
                    std::process::exit(0);
                }
                _ => return Err(TpmError::from(arg.unexpected())),
            }
        }
        Ok(Commands::StartSession(args))
    }

    /// Runs `start-session`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, log_format: cli::LogFormat) -> Result<(), TpmError> {
        let mut nonce_bytes = vec![0; 16];
        thread_rng().fill_bytes(&mut nonce_bytes);

        let auth_hash = TpmAlgId::from(self.hash_alg);
        let session_type = self.session_type;

        let cmd = TpmStartAuthSessionCommand {
            nonce_caller: Tpm2b::try_from(nonce_bytes.as_slice())?,
            encrypted_salt: Tpm2b::default(),
            session_type: session_type.into(),
            symmetric: TpmtSymDefObject::default(),
            auth_hash,
        };

        let handles = [TpmRh::Null as u32, TpmRh::Null as u32];
        let (response, _) = chip.execute(&cmd, Some(&handles), &[], log_format)?;

        let start_auth_session_resp = response
            .StartAuthSession()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        let digest_len = tpm2_protocol::tpm_hash_size(&auth_hash)
            .ok_or_else(|| TpmError::Execution("Unsupported hash algorithm".to_string()))?;

        let data = SessionData {
            handle: start_auth_session_resp.session_handle.into(),
            nonce_tpm: base64_engine.encode(&*start_auth_session_resp.nonce_tpm),
            attributes: TpmaSession::CONTINUE_SESSION.bits(),
            hmac_key: base64_engine.encode(Vec::<u8>::new()),
            auth_hash: cmd.auth_hash as u16,
            policy_digest: hex::encode(vec![0; digest_len]),
        };

        let envelope = Envelope {
            version: 1,
            object_type: "session".to_string(),
            data: data.to_json(),
        };

        let envelope_value = envelope.to_json();
        let output_object = Object::Context(envelope_value);
        let json_line = output_object.to_json().dump();
        println!("{json_line}");

        Ok(())
    }
}
