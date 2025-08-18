// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use std::{convert::TryFrom, io::IsTerminal, string::ToString, vec::Vec};
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bMaxBuffer, Tpm2bNonce, TpmAlgId, TpmCap, TpmCc, TpmRc,
        TpmRcBase, TpmRcIndex, TpmRh, TpmaSession, TpmlPcrSelection, TpmtSymDef, TpmuSymKeyBits,
        TpmuSymMode,
    },
    message::{
        tpm_build_command, tpm_build_response, tpm_parse_command, tpm_parse_response,
        TpmAuthCommands, TpmCommandBody, TpmContextSaveCommand, TpmEvictControlCommand,
        TpmFlushContextCommand, TpmFlushContextResponse, TpmGetCapabilityCommand, TpmHashCommand,
        TpmPcrEventResponse, TpmPcrReadCommand, TpmPcrReadResponse,
    },
    TpmBuffer, TpmBuild, TpmErrorKind, TpmParse, TpmPersistent, TpmSession, TpmWriter,
    TPM_MAX_COMMAND_SIZE,
};

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 {
        return Err("Hex string must have an even number of characters");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "Invalid hex character")
}

fn test_rc_base_from_raw_rc() {
    let cases = [
        ("TPM_RC_SUCCESS", 0x0000, TpmRcBase::Success),
        ("TPM_RC_BAD_TAG", 0x001E, TpmRcBase::BadTag),
        ("TPM_RC_INITIALIZE", 0x0100, TpmRcBase::Initialize),
        ("TPM_RC_FAILURE", 0x0101, TpmRcBase::Failure),
        ("TPM_RC_SENSITIVE", 0x0155, TpmRcBase::Sensitive),
        ("TPM_RC_CONTEXT_GAP", 0x0901, TpmRcBase::ContextGap),
        ("TPM_RC_NV_UNAVAILABLE", 0x0923, TpmRcBase::NvUnavailable),
        (
            "TPM_RC_HANDLE with handle index 1",
            0x018B,
            TpmRcBase::Handle,
        ),
        (
            "TPM_RC_ATTRIBUTES with handle index 4",
            0x0482,
            TpmRcBase::Attributes,
        ),
        (
            "TPM_RC_AUTH_FAIL with session index 0",
            0x088E,
            TpmRcBase::AuthFail,
        ),
        (
            "TPM_RC_CURVE with parameter index 1",
            0x01E6,
            TpmRcBase::Curve,
        ),
    ];

    for (description, raw_rc, expected_base) in cases {
        let rc = TpmRc::try_from(raw_rc).unwrap();
        assert_eq!(rc.base(), Ok(expected_base), "{description}");
    }
}

fn test_rc_index_from_value() {
    let cases = [
        ("No index for success", 0x0000, None),
        ("No index for format 0", 0x0101, None),
        ("No index for warning", 0x0901, None),
        ("No index when N is 0", 0x008B, None),
        ("Parameter index 1", 0x01C1, Some(TpmRcIndex::Parameter(1))),
        ("Parameter index 8", 0x08C4, Some(TpmRcIndex::Parameter(8))),
        ("Handle index 1", 0x018B, Some(TpmRcIndex::Handle(1))),
        ("Handle index 7", 0x078B, Some(TpmRcIndex::Handle(7))),
        ("Session index 0", 0x088E, Some(TpmRcIndex::Session(0))),
        ("Session index 7", 0x0F8E, Some(TpmRcIndex::Session(7))),
    ];

    for (description, raw_rc, expected) in cases {
        let rc = TpmRc::try_from(raw_rc).unwrap();
        assert_eq!(rc.index(), expected, "{description}");
    }
}

fn test_rc_display() {
    let cases = [
        ("TPM_RC_SUCCESS", 0x0000, "TPM_RC_SUCCESS"),
        (
            "TPM_RC_HANDLE with handle index 1",
            0x018B,
            "[TPM_RC_HANDLE, handle[1]]",
        ),
        (
            "TPM_RC_ATTRIBUTES with handle index 4",
            0x0482,
            "[TPM_RC_ATTRIBUTES, handle[4]]",
        ),
        (
            "TPM_RC_AUTH_FAIL with session index 0",
            0x088E,
            "[TPM_RC_AUTH_FAIL, session[0]]",
        ),
        (
            "TPM_RC_NV_UNAVAILABLE (warning) without index",
            0x0923,
            "TPM_RC_NV_UNAVAILABLE",
        ),
    ];

    for (description, raw_rc, expected_display) in cases {
        let rc = TpmRc::try_from(raw_rc).unwrap();
        assert_eq!(rc.to_string(), expected_display, "{description}");
    }
}

fn test_build_get_capability_command() {
    let cmd = TpmGetCapabilityCommand {
        cap: TpmCap::Algs,
        property: 1,
        property_count: 128,
    };
    let mut buf = [0u8; 1024];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        tpm_build_command(
            &cmd,
            tpm2_protocol::data::TpmSt::NoSessions,
            None,
            &[],
            &mut writer,
        )
        .unwrap();
        writer.len()
    };
    let generated_bytes = &buf[..len];
    let expected_bytes = hex_to_bytes("8001000000160000017a000000000000000100000080").unwrap();

    assert_eq!(generated_bytes, expected_bytes.as_slice(),);
}

fn test_build_hash_command() {
    let cmd = TpmHashCommand {
        data: Tpm2bMaxBuffer::try_from(&b"hello"[..]).unwrap(),
        hash_alg: TpmAlgId::Sha256,
        hierarchy: TpmRh::Owner,
    };
    let mut buf = [0u8; 1024];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        tpm_build_command(
            &cmd,
            tpm2_protocol::data::TpmSt::NoSessions,
            None,
            &[],
            &mut writer,
        )
        .unwrap();
        writer.len()
    };
    let generated_bytes = &buf[..len];
    let expected_bytes = hex_to_bytes("8001000000170000017d000568656c6c6f000b40000001").unwrap();

    assert_eq!(generated_bytes, expected_bytes.as_slice(),);
}

fn test_build_pcr_read_response() {
    let mut pcr_values = tpm2_protocol::data::TpmlDigest::new();
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

fn test_build_error_response() {
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

fn test_parse_tpm_pcr_event_response() {
    let mut digests = tpm2_protocol::data::TpmlDigestValues::new();
    digests
        .try_push(tpm2_protocol::data::TpmtHa {
            hash_alg: TpmAlgId::Sha256,
            digest: tpm2_protocol::data::TpmuHa::Sha256([0xA1; 32]),
        })
        .unwrap();
    let original_resp = TpmPcrEventResponse { digests };

    let mut sessions = tpm2_protocol::message::TpmAuthResponses::new();
    sessions
        .try_push(tpm2_protocol::data::TpmsAuthResponse {
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

    let (rc, parsed_resp, parsed_sessions) = tpm_parse_response(TpmCc::PcrEvent, &generated_bytes)
        .unwrap()
        .unwrap();

    assert_eq!(rc.value(), 0);
    let resp = parsed_resp.PcrEvent().unwrap();

    assert_eq!(resp, original_resp);
    assert_eq!(parsed_sessions, sessions);
}

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
            tpm_build_command(
                &cmd,
                tpm2_protocol::data::TpmSt::NoSessions,
                None,
                &[],
                &mut writer,
            )
            .unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    let expected_bytes = hex_to_bytes("8001000000160000017a000000000000000100000080").unwrap();
    assert_eq!(generated_bytes, expected_bytes.as_slice());

    match tpm_parse_command(&generated_bytes) {
        Ok((_handles, cmd_data, sessions)) => {
            assert_eq!(cmd_data, TpmCommandBody::GetCapability(cmd));
            if !sessions.is_empty() {
                panic!("sessions should be empty");
            }
        }
        Err(e) => panic!("command parsing failed: {e:?}"),
    }
}

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
            tpm_build_command(
                &cmd,
                tpm2_protocol::data::TpmSt::NoSessions,
                None,
                &[],
                &mut writer,
            )
            .unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    let expected_bytes =
        hex_to_bytes("8001000000320000017d0020dededededededededededededededededededededededededededededededede000b40000001").unwrap();
    assert_eq!(generated_bytes, expected_bytes.as_slice());

    match tpm_parse_command(&generated_bytes) {
        Ok((_handles, cmd_data, sessions)) => {
            assert_eq!(cmd_data, TpmCommandBody::Hash(cmd));
            if !sessions.is_empty() {
                panic!("sessions should be empty");
            }
        }
        Err(e) => panic!("command parsing failed: {e:?}"),
    }
}

fn test_parse_flush_context_command() {
    let cmd = TpmFlushContextCommand {
        flush_handle: 0x8000_0000,
    };

    let generated_bytes = {
        let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_build_command(
                &cmd,
                tpm2_protocol::data::TpmSt::NoSessions,
                None,
                &[],
                &mut writer,
            )
            .unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    let expected_bytes = hex_to_bytes("80010000000e0000016580000000").unwrap();
    assert_eq!(generated_bytes, expected_bytes.as_slice());

    match tpm_parse_command(&generated_bytes) {
        Ok((_handles, cmd_data, sessions)) => {
            assert_eq!(cmd_data, TpmCommandBody::FlushContext(cmd));
            if !sessions.is_empty() {
                panic!("sessions should be empty");
            }
        }
        Err(e) => panic!("command parsing failed: {e:?}"),
    }
}

fn test_parse_pcr_read_command() {
    let mut pcr_selection = tpm2_protocol::data::TpmlPcrSelection::new();
    pcr_selection
        .try_push(tpm2_protocol::data::TpmsPcrSelection {
            hash: TpmAlgId::Sha256,
            pcr_select: tpm2_protocol::data::TpmsPcrSelect::try_from(&[0xFF, 0x80, 0x01][..])
                .unwrap(),
        })
        .unwrap();

    let cmd = TpmPcrReadCommand {
        pcr_selection_in: pcr_selection,
    };

    let generated_bytes = {
        let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_build_command(
                &cmd,
                tpm2_protocol::data::TpmSt::NoSessions,
                None,
                &[],
                &mut writer,
            )
            .unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    let expected_bytes = hex_to_bytes("8001000000140000017e00000001000b03ff8001").unwrap();
    assert_eq!(generated_bytes, expected_bytes.as_slice());

    match tpm_parse_command(&generated_bytes) {
        Ok((_handles, cmd_data, sessions)) => {
            assert_eq!(cmd_data, TpmCommandBody::PcrRead(cmd.clone()));
            if !sessions.is_empty() {
                panic!("sessions should be empty");
            }
        }
        Err(e) => panic!("command parsing failed: {e:?}"),
    }
}

fn test_parse_context_save_command() {
    let cmd = TpmContextSaveCommand {};
    let save_handle = 0x8000_0001;
    let handles = [save_handle];

    let generated_bytes = {
        let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_build_command(
                &cmd,
                tpm2_protocol::data::TpmSt::NoSessions,
                Some(&handles),
                &[],
                &mut writer,
            )
            .unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    let expected_bytes = hex_to_bytes("80010000000e0000016280000001").unwrap();
    assert_eq!(generated_bytes, expected_bytes.as_slice());

    match tpm_parse_command(&generated_bytes) {
        Ok((res_handles, cmd_data, sessions)) => {
            assert_eq!(res_handles.as_ref(), handles);
            assert_eq!(cmd_data, TpmCommandBody::ContextSave(cmd));
            if !sessions.is_empty() {
                panic!("sessions should be empty");
            }
        }
        Err(e) => panic!("command parsing failed: {e:?}"),
    }
}

fn test_parse_evict_control_command() {
    let cmd = TpmEvictControlCommand {
        persistent_handle: TpmPersistent(0x8100_0001),
    };
    let handles = [TpmRh::Owner as u32, 0x8000_0000];
    let mut sessions = TpmAuthCommands::new();
    sessions
        .try_push(tpm2_protocol::data::TpmsAuthCommand {
            session_handle: TpmSession(TpmRh::Password as u32),
            nonce: tpm2_protocol::data::Tpm2bNonce::default(),
            session_attributes: tpm2_protocol::data::TpmaSession::default(),
            hmac: tpm2_protocol::data::Tpm2bAuth::try_from(&b"123"[..]).unwrap(),
        })
        .unwrap();

    let generated_bytes = {
        let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_build_command(
                &cmd,
                tpm2_protocol::data::TpmSt::Sessions,
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

fn test_response_macro_parse_correctness() {
    let mut digests = tpm2_protocol::data::TpmlDigestValues::new();
    digests
        .try_push(tpm2_protocol::data::TpmtHa {
            hash_alg: TpmAlgId::Sha256,
            digest: tpm2_protocol::data::TpmuHa::Sha256([0xA1; 32]),
        })
        .unwrap();
    let original_resp = TpmPcrEventResponse { digests };

    let mut body_buf = [0u8; 1024];
    let body_len = {
        let mut writer = TpmWriter::new(&mut body_buf);
        original_resp.build(&mut writer).unwrap();
        writer.len()
    };
    let response_body_bytes = &body_buf[..body_len];

    assert_eq!(body_len, 42);
    assert_eq!(&response_body_bytes[0..4], &38u32.to_be_bytes());

    let result = TpmPcrEventResponse::parse(response_body_bytes);

    assert!(result.is_ok(), "command parsing failed: {:?}", result.err());
    let (parsed_resp, tail) = result.unwrap();
    assert_eq!(parsed_resp, original_resp, "response mismatch");
    assert!(tail.is_empty(), "tail data");
}

fn test_parse_build_tpmt_sym_def_xor() {
    let original_sym_def = TpmtSymDef {
        algorithm: TpmAlgId::Xor,
        key_bits: TpmuSymKeyBits::Xor(TpmAlgId::Sha256),
        mode: TpmuSymMode::Xor(TpmAlgId::Null),
    };

    let mut buf = [0u8; 1024];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        original_sym_def.build(&mut writer).unwrap();
        writer.len()
    };
    let built_bytes = &buf[..len];

    let (parsed_sym_def, remainder) = TpmtSymDef::parse(built_bytes).unwrap();

    assert_eq!(
        parsed_sym_def, original_sym_def,
        "Parsed TpmtSymDef does not match original"
    );
    assert!(
        remainder.is_empty(),
        "Buffer not fully consumed after parsing TpmtSymDef"
    );
}

fn test_buffer_slice_larger_than_capacity() {
    const CAPACITY: usize = 66_000;
    const DATA_LEN: usize = 66_000;
    let data = vec![0; DATA_LEN];

    let buffer = TpmBuffer::<CAPACITY>::try_from(data.as_slice()).unwrap();

    let mut out_buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let mut writer = TpmWriter::new(&mut out_buf);
    let result = buffer.build(&mut writer);

    assert_eq!(
        result,
        Err(TpmErrorKind::ValueTooLarge),
        "Should reject building buffers with lengths that do not fit in a u16"
    );
}

fn print_ok() {
    if std::io::stderr().is_terminal() {
        println!("\x1B[32mOK\x1B[0m");
    } else {
        println!("OK");
    }
}

fn print_failed() {
    if std::io::stderr().is_terminal() {
        println!("\x1B[31mFAILED\x1B[0m");
    } else {
        println!("FAILED");
    }
}

fn run_all_tests() -> usize {
    let tests: &[(&str, fn())] = &[
        ("test_rc_base_from_raw_rc", test_rc_base_from_raw_rc),
        ("test_rc_index_from_value", test_rc_index_from_value),
        ("test_rc_display", test_rc_display),
        (
            "test_build_get_capability_command",
            test_build_get_capability_command,
        ),
        ("test_build_hash_command", test_build_hash_command),
        ("test_build_pcr_read_response", test_build_pcr_read_response),
        ("test_build_error_response", test_build_error_response),
        (
            "test_parse_tpm_pcr_event_response",
            test_parse_tpm_pcr_event_response,
        ),
        (
            "test_parse_get_capability_command",
            test_parse_get_capability_command,
        ),
        ("test_parse_hash_command", test_parse_hash_command),
        (
            "test_parse_flush_context_command",
            test_parse_flush_context_command,
        ),
        ("test_parse_pcr_read_command", test_parse_pcr_read_command),
        (
            "test_parse_context_save_command",
            test_parse_context_save_command,
        ),
        (
            "test_parse_evict_control_command",
            test_parse_evict_control_command,
        ),
        (
            "test_response_macro_parse_correctness",
            test_response_macro_parse_correctness,
        ),
        (
            "test_parse_build_tpmt_sym_def_xor",
            test_parse_build_tpmt_sym_def_xor,
        ),
        (
            "test_buffer_slice_larger_than_capacity",
            test_buffer_slice_larger_than_capacity,
        ),
    ];

    let mut failed = 0;
    println!("Running {} tests...", tests.len());
    for (name, test) in tests {
        print!("Test {name} ... ");
        let result = std::panic::catch_unwind(test);
        if result.is_err() {
            print_failed();
            failed += 1;
        } else {
            print_ok();
        }
    }
    failed
}

fn main() {
    let failed = run_all_tests();
    if failed > 0 {
        eprintln!("\n{failed} test(s) failed.");
        std::process::exit(1);
    }
    eprintln!("\nAll tests passed.");
}
