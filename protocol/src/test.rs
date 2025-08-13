// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bMaxBuffer, Tpm2bNonce, TpmAlgId, TpmCap, TpmCc, TpmRc,
        TpmRcBase, TpmRcIndex, TpmRh, TpmaSession, TpmlPcrSelection,
    },
    message::{
        tpm_build_command, tpm_build_response, tpm_parse_command, tpm_parse_response,
        TpmAuthCommands, TpmCommandBody, TpmEvictControlCommand, TpmFlushContextResponse,
        TpmGetCapabilityCommand, TpmHashCommand, TpmPcrEventResponse, TpmPcrReadResponse,
    },
    TpmPersistent, TpmSession, TpmSized, TpmWriter, TPM_MAX_COMMAND_SIZE,
};
use rstest::rstest;
use std::{convert::TryFrom, string::ToString};

#[rstest]
#[case("TPM_RC_SUCCESS", 0x0000, TpmRcBase::Success)]
#[case("TPM_RC_BAD_TAG", 0x001E, TpmRcBase::BadTag)]
#[case("TPM_RC_INITIALIZE", 0x0100, TpmRcBase::Initialize)]
#[case("TPM_RC_FAILURE", 0x0101, TpmRcBase::Failure)]
#[case("TPM_RC_SENSITIVE", 0x0155, TpmRcBase::Sensitive)]
#[case("TPM_RC_CONTEXT_GAP", 0x0901, TpmRcBase::ContextGap)]
#[case("TPM_RC_NV_UNAVAILABLE", 0x0923, TpmRcBase::NvUnavailable)]
#[case("TPM_RC_HANDLE with handle index 1", 0x018B, TpmRcBase::Handle)]
#[case("TPM_RC_ATTRIBUTES with handle index 4", 0x0482, TpmRcBase::Attributes)]
#[case("TPM_RC_AUTH_FAIL with session index 1", 0x088E, TpmRcBase::AuthFail)]
#[case("TPM_RC_CURVE with parameter index 1", 0x01E6, TpmRcBase::Curve)]
fn test_tpm_rc_base_from_raw_rc(
    #[case] description: &str,
    #[case] raw_rc: u32,
    #[case] expected_base: TpmRcBase,
) {
    let rc = TpmRc::try_from(raw_rc).unwrap();
    assert_eq!(rc.base(), Ok(expected_base), "{description}");
}

#[rstest]
#[case("No index for success", 0x0000, None)]
#[case("No index for format 0", 0x0101, None)]
#[case("No index for warning", 0x0901, None)]
#[case("No index when N is 0", 0x008B, None)]
#[case("Parameter index 1", 0x01C1, Some(TpmRcIndex::Parameter(1)))]
#[case("Parameter index 8", 0x08C4, Some(TpmRcIndex::Parameter(8)))]
#[case("Handle index 1", 0x018B, Some(TpmRcIndex::Handle(1)))]
#[case("Handle index 7", 0x078B, Some(TpmRcIndex::Handle(7)))]
#[case("Session index 1", 0x088E, Some(TpmRcIndex::Session(1)))]
#[case("Session index 8", 0x0F8E, Some(TpmRcIndex::Session(8)))]
fn test_tpm_rc_index_from_value(
    #[case] description: &str,
    #[case] raw_rc: u32,
    #[case] expected: Option<TpmRcIndex>,
) {
    let rc = TpmRc::try_from(raw_rc).unwrap();
    assert_eq!(rc.index(), expected, "{description}");
}

#[rstest]
#[case("TPM_RC_SUCCESS", 0x0000, "TPM_RC_SUCCESS")]
#[case(
    "TPM_RC_HANDLE with handle index 1",
    0x018B,
    "[TPM_RC_HANDLE, handle[1]]"
)]
#[case(
    "TPM_RC_ATTRIBUTES with handle index 4",
    0x0482,
    "[TPM_RC_ATTRIBUTES, handle[4]]"
)]
#[case(
    "TPM_RC_AUTH_FAIL with session index 1",
    0x088E,
    "[TPM_RC_AUTH_FAIL, session[1]]"
)]
#[case(
    "TPM_RC_NV_UNAVAILABLE (warning) without index",
    0x0923,
    "TPM_RC_NV_UNAVAILABLE"
)]
fn test_tpm_rc_display(
    #[case] description: &str,
    #[case] raw_rc: u32,
    #[case] expected_display: &str,
) {
    let rc = TpmRc::try_from(raw_rc).unwrap();
    assert_eq!(rc.to_string(), expected_display, "{description}");
}

#[test]
fn test_tpm_build_get_capability_command() {
    let cmd = TpmGetCapabilityCommand {
        cap: TpmCap::Algs,
        property: 1,
        property_count: 128,
    };
    let mut buf = [0u8; 1024];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        tpm_build_command(&cmd, crate::data::TpmSt::NoSessions, None, &[], &mut writer).unwrap();
        writer.len()
    };
    let generated_bytes = &buf[..len];
    let expected_bytes = hex::decode("8001000000160000017a000000000000000100000080").unwrap();

    assert_eq!(generated_bytes, expected_bytes.as_slice(),);
}

#[test]
fn test_tpm_build_hash_command() {
    let cmd = TpmHashCommand {
        data: Tpm2bMaxBuffer::try_from(&b"hello"[..]).unwrap(),
        hash_alg: TpmAlgId::Sha256,
        hierarchy: TpmRh::Owner,
    };
    let mut buf = [0u8; 1024];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        tpm_build_command(&cmd, crate::data::TpmSt::NoSessions, None, &[], &mut writer).unwrap();
        writer.len()
    };
    let generated_bytes = &buf[..len];
    let expected_bytes = hex::decode("8001000000170000017d000568656c6c6f000b40000001").unwrap();

    assert_eq!(generated_bytes, expected_bytes.as_slice(),);
}

#[rstest]
fn test_tpm_build_pcr_read_response() {
    let mut pcr_values = crate::data::TpmlDigest::new();
    pcr_values
        .try_push(Tpm2bDigest::try_from(&[0xDE; 32][..]).unwrap())
        .unwrap();

    let resp = TpmPcrReadResponse {
        pcr_update_counter: 1,
        pcr_selection_out: TpmlPcrSelection::default(),
        pcr_values,
    };
    let rc = TpmRc::try_from(TpmRcBase::Success as u32).unwrap();

    let mut buf = [0u8; 1024];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        tpm_build_response(&resp, &[], rc, &mut writer).unwrap();
        writer.len()
    };
    let generated_bytes = &buf[..len];

    let expected_bytes: &[u8] = &[
        0x80, 0x01, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE,
        0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE,
        0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE,
    ];

    assert_eq!(generated_bytes, expected_bytes);
}

#[rstest]
fn test_tpm_build_error_response() {
    let resp = TpmFlushContextResponse::default();
    let rc = TpmRc::try_from(TpmRcBase::Failure as u32).unwrap();

    let generated_bytes = {
        let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_build_response(&resp, &[], rc, &mut writer).unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    assert_eq!(generated_bytes.len(), 10);
    assert_eq!(&generated_bytes[0..2], &[0x80, 0x01]);
    assert_eq!(&generated_bytes[2..6], &10u32.to_be_bytes());
    assert_eq!(
        &generated_bytes[6..10],
        &(TpmRcBase::Failure as u32).to_be_bytes()
    );
}

#[rstest]
fn test_tpm_parse_tpm_pcr_event_response() {
    let mut digests = crate::data::TpmlDigestValues::new();
    digests
        .try_push(crate::data::TpmtHa {
            hash_alg: TpmAlgId::Sha256,
            digest: crate::data::TpmuHa::Sha256([0xA1; 32]),
        })
        .unwrap();
    let original_resp = TpmPcrEventResponse { digests };

    let mut sessions = crate::message::TpmAuthResponses::new();
    sessions
        .try_push(crate::data::TpmsAuthResponse {
            nonce: Tpm2bNonce::try_from(&[0xAA; 8][..]).unwrap(),
            session_attributes: TpmaSession::CONTINUE_SESSION,
            hmac: Tpm2bAuth::try_from(&[0xBB; 32][..]).unwrap(),
        })
        .unwrap();
    let rc = TpmRc::try_from(TpmRcBase::Success as u32).unwrap();

    let generated_bytes = {
        let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_build_response(&original_resp, &sessions, rc, &mut writer).unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    let (parsed_resp, parsed_sessions) = tpm_parse_response(TpmCc::PcrEvent, &generated_bytes)
        .unwrap()
        .unwrap();

    let resp = parsed_resp.PcrEvent().unwrap();

    assert_eq!(resp, original_resp);
    assert_eq!(parsed_sessions, sessions);
}

#[rstest]
fn test_parse_get_capability_command() {
    let cmd = TpmGetCapabilityCommand {
        cap: TpmCap::Algs,
        property: 1,
        property_count: 128,
    };

    let generated_bytes = {
        let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_build_command(&cmd, crate::data::TpmSt::NoSessions, None, &[], &mut writer)
                .unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    let (_handles, cmd_data, sessions) = tpm_parse_command(&generated_bytes).unwrap();

    assert!(sessions.is_empty());
    assert_eq!(cmd_data, TpmCommandBody::GetCapability(cmd));
}

#[rstest]
fn test_parse_hash_command() {
    let cmd = TpmHashCommand {
        data: Tpm2bMaxBuffer::try_from(&[0xDE; 32][..]).unwrap(),
        hash_alg: TpmAlgId::Sha256,
        hierarchy: TpmRh::Owner,
    };

    let generated_bytes = {
        let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_build_command(&cmd, crate::data::TpmSt::NoSessions, None, &[], &mut writer)
                .unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    let (_handles, cmd_data, sessions) = tpm_parse_command(&generated_bytes).unwrap();
    assert!(sessions.is_empty());
    assert_eq!(cmd_data, TpmCommandBody::Hash(cmd));
}

#[rstest]
fn test_parse_evict_control_command() {
    let cmd = TpmEvictControlCommand {
        persistent_handle: TpmPersistent(0x8100_0001),
    };
    let handles = [TpmRh::Owner as u32, 0x8000_0000];
    let mut sessions = TpmAuthCommands::new();
    sessions
        .try_push(crate::data::TpmsAuthCommand {
            session_handle: TpmSession(TpmRh::Password as u32),
            nonce: crate::data::Tpm2bNonce::default(),
            session_attributes: crate::data::TpmaSession::default(),
            hmac: crate::data::Tpm2bAuth::try_from(&b"123"[..]).unwrap(),
        })
        .unwrap();

    let generated_bytes = {
        let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_build_command(
                &cmd,
                crate::data::TpmSt::Sessions,
                Some(&handles),
                &sessions,
                &mut writer,
            )
            .unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    let (res_handles, res_cmd_data, res_sessions) = tpm_parse_command(&generated_bytes).unwrap();

    assert_eq!(res_handles.as_ref(), handles);
    assert_eq!(res_sessions, sessions);
    assert_eq!(res_cmd_data, TpmCommandBody::EvictControl(cmd));
}
