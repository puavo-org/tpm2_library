// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{SessionType, StartSession},
    AuthSession, Command, Envelope, SessionData, TpmDevice, TpmError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use rand::{thread_rng, RngCore};
use tpm2_protocol::{
    data::{
        Tpm2b, TpmAlgId, TpmRh, TpmSe, TpmaSession, TpmtSymDefObject, TpmuSymKeyBits, TpmuSymMode,
    },
    message::TpmStartAuthSessionCommand,
};

impl Command for StartSession {
    /// Runs `start-session`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self, chip: &mut TpmDevice, _session: Option<&AuthSession>) -> Result<(), TpmError> {
        let mut nonce_bytes = vec![0; 16];
        thread_rng().fill_bytes(&mut nonce_bytes);

        let auth_hash = TpmAlgId::from(self.hash_alg);

        let cmd = TpmStartAuthSessionCommand {
            nonce_caller: Tpm2b::try_from(nonce_bytes.as_slice())?,
            encrypted_salt: Tpm2b::default(),
            session_type: match self.session_type {
                SessionType::Hmac => TpmSe::Hmac,
                SessionType::Policy => TpmSe::Policy,
                SessionType::Trial => TpmSe::Trial,
            },
            symmetric: TpmtSymDefObject {
                algorithm: TpmAlgId::Null,
                key_bits: TpmuSymKeyBits::Null,
                mode: TpmuSymMode::Null,
            },
            auth_hash,
        };

        let handles = [TpmRh::Null as u32, TpmRh::Null as u32];
        let (response, _) = chip.execute(&cmd, Some(&handles), &[])?;

        let start_auth_session_resp = response
            .StartAuthSession()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        let digest_len = tpm2_protocol::tpm_hash_size(&auth_hash).ok_or(TpmError::Execution(
            "Unsupported hash algorithm".to_string(),
        ))?;

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
            data: serde_json::to_value(data)?,
        };

        let json_out = serde_json::to_string_pretty(&envelope)?;
        println!("{json_out}");

        Ok(())
    }
}
