// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use std::{
    any::Any, collections::HashMap, convert::TryFrom, fmt::Debug, io::IsTerminal, mem::size_of,
    string::ToString, vec::Vec,
};
use tpm2_protocol::{
    build_tpm2b,
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bMaxBuffer, Tpm2bMaxNvBuffer, Tpm2bNonce, TpmAlgId, TpmCap,
        TpmCc, TpmRc, TpmRcBase, TpmRcIndex, TpmRh, TpmaSession, TpmlPcrSelection, TpmsAuthCommand,
        TpmsClockInfo, TpmtSymDef, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{
        tpm_build_command, tpm_build_response, tpm_parse_command, tpm_parse_response,
        TpmAuthCommands, TpmCommandBody, TpmContextSaveCommand, TpmEvictControlCommand,
        TpmFlushContextCommand, TpmFlushContextResponse, TpmGetCapabilityCommand, TpmHashCommand,
        TpmNvWriteCommand, TpmPcrEventResponse, TpmPcrReadCommand, TpmPcrReadResponse,
        TpmPolicyGetDigestResponse,
    },
    TpmBuffer, TpmBuild, TpmErrorKind, TpmParse, TpmPersistent, TpmSession, TpmSized, TpmWriter,
    TPM_MAX_COMMAND_SIZE,
};

/// A linear congruential generator (LCG) implementation.
struct Rng {
    seed: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { seed }
    }

    fn next_u16(&mut self) -> u16 {
        self.seed = self.seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.seed >> 32) as u16
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u16() as u8
    }

    fn next_u32(&mut self) -> u32 {
        ((self.next_u16() as u32) << 16) | (self.next_u16() as u32)
    }

    fn next_u64(&mut self) -> u64 {
        ((self.next_u32() as u64) << 32) | (self.next_u32() as u64)
    }

    fn gen_range(&mut self, range: std::ops::Range<u8>) -> u8 {
        range.start + (self.next_u8() % (range.end - range.start))
    }
}

pub trait TpmObject: Any + Debug {
    fn build(&self, writer: &mut TpmWriter) -> Result<(), TpmErrorKind>;
    fn as_any(&self) -> &dyn Any;
    fn dyn_eq(&self, other: &dyn TpmObject) -> bool;
}

impl<T> TpmObject for T
where
    T: TpmBuild + TpmParse + PartialEq + Any + Debug,
{
    fn build(&self, writer: &mut TpmWriter) -> Result<(), TpmErrorKind> {
        TpmBuild::build(self, writer)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn dyn_eq(&self, other: &dyn TpmObject) -> bool {
        other
            .as_any()
            .downcast_ref::<T>()
            .map_or(false, |a| self == a)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(u8)]
enum TypeId {
    Clock = 0,
    Alg = 1,
    SessionAttrs = 2,
}

impl TryFrom<u8> for TypeId {
    type Error = TpmErrorKind;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Clock),
            1 => Ok(Self::Alg),
            2 => Ok(Self::SessionAttrs),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

type ObjectParser = fn(&[u8]) -> Result<(Box<dyn TpmObject>, &[u8]), TpmErrorKind>;

fn make_parser<T: TpmParse + TpmObject>() -> ObjectParser {
    |bytes: &[u8]| {
        let (obj, remainder) = T::parse(bytes)?;
        Ok((Box::new(obj), remainder))
    }
}

fn random_object(rng: &mut Rng) -> (TypeId, Box<dyn TpmObject>) {
    match rng.gen_range(0..3) {
        0 => (
            TypeId::Clock,
            Box::new(TpmsClockInfo {
                clock: rng.next_u64(),
                reset_count: rng.next_u32(),
                restart_count: rng.next_u32(),
                safe: (rng.next_u8() % 2 == 0).into(),
            }),
        ),
        1 => {
            let alg = loop {
                if let Ok(alg) = TpmAlgId::try_from(rng.next_u16()) {
                    break alg;
                }
            };
            (TypeId::Alg, Box::new(alg))
        }
        _ => (
            TypeId::SessionAttrs,
            Box::new(TpmaSession::from_bits_truncate(rng.next_u8())),
        ),
    }
}

fn test_dynamic_roundtrip_blind_parse() {
    let mut parsers: HashMap<TypeId, ObjectParser> = HashMap::new();
    parsers.insert(TypeId::Clock, make_parser::<TpmsClockInfo>());
    parsers.insert(TypeId::Alg, make_parser::<TpmAlgId>());
    parsers.insert(TypeId::SessionAttrs, make_parser::<TpmaSession>());

    const LIST_SIZE: usize = 100;
    let mut rng = Rng::new(12345);
    let (type_list, original_list): (Vec<_>, Vec<_>) =
        (0..LIST_SIZE).map(|_| random_object(&mut rng)).unzip();
    let mut byte_stream = [0u8; TPM_MAX_COMMAND_SIZE];
    let final_len = {
        let mut writer = TpmWriter::new(&mut byte_stream);
        for i in 0..LIST_SIZE {
            let type_id = type_list[i];
            let item = &original_list[i];
            TpmBuild::build(&(type_id as u8), &mut writer).unwrap();
            item.build(&mut writer).unwrap();
        }
        writer.len()
    };
    let written_bytes = &byte_stream[..final_len];

    let mut parsed_list: Vec<Box<dyn TpmObject>> = Vec::with_capacity(LIST_SIZE);
    let mut remaining_bytes = written_bytes;

    while !remaining_bytes.is_empty() {
        let (tag_byte, stream_after_tag) = u8::parse(remaining_bytes).unwrap();
        let type_id = TypeId::try_from(tag_byte).unwrap();

        let parser_fn = parsers.get(&type_id).expect("Parser not registered!");

        let (parsed_obj, next_bytes) = parser_fn(stream_after_tag).unwrap();
        parsed_list.push(parsed_obj);
        remaining_bytes = next_bytes;
    }

    assert!(
        remaining_bytes.is_empty(),
        "Byte stream had trailing data after parsing."
    );
    assert_eq!(original_list.len(), parsed_list.len());
    for i in 0..LIST_SIZE {
        assert!(
            original_list[i].dyn_eq(parsed_list[i].as_ref()),
            "Mismatch at index {i}"
        );
    }
}

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

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn test_tpm_rc_base_from_raw() {
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

fn test_tpm_rc_index_from_raw() {
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

fn test_tpm_rc_display() {
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

fn test_command_build_get_capability() {
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

fn test_command_build_hash() {
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

fn test_response_build_pcr_read() {
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

    assert_eq!(bytes_to_hex(generated_bytes), bytes_to_hex(expected_bytes));
}

fn test_response_build_error() {
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

fn test_response_parse_pcr_event() {
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

fn test_command_parse_get_capability() {
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
                panic!("Sessions should be empty");
            }
        }
        Err(e) => panic!("Parsing failed: {e:?}"),
    }
}

fn test_command_parse_hash() {
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
                panic!("Sessions should be empty");
            }
        }
        Err(e) => panic!("Parsing failed: {e:?}"),
    }
}

fn test_command_parse_flush_context() {
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
                panic!("Sessions should be empty");
            }
        }
        Err(e) => panic!("Parsing failed: {e:?}"),
    }
}

fn test_command_parse_pcr_read() {
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
                panic!("Sessions should be empty");
            }
        }
        Err(e) => panic!("Parsing failed: {e:?}"),
    }
}

fn test_command_parse_context_save() {
    let cmd = TpmContextSaveCommand {
        save_handle: 0x8000_0001.into(),
    };

    let generated_bytes = {
        let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_build_command(
                &cmd,
                tpm2_protocol::data::TpmSt::NoSessions,
                &[],
                &mut writer,
            )
            .unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    assert_eq!(
        bytes_to_hex(&generated_bytes),
        "80010000000e0000016280000001"
    );

    match tpm_parse_command(&generated_bytes) {
        Ok((res_handles, cmd_data, sessions)) => {
            let handles = [cmd.save_handle.0];
            assert_eq!(res_handles.as_ref(), handles);
            assert_eq!(cmd_data, TpmCommandBody::ContextSave(cmd));
            if !sessions.is_empty() {
                panic!("Sessions should be empty");
            }
        }
        Err(e) => panic!("Parsing failed: {e:?}"),
    }
}

fn test_command_parse_evict_control() {
    let cmd = TpmEvictControlCommand {
        auth: (TpmRh::Owner as u32).into(),
        object_handle: 0x8000_0000.into(),
        persistent_handle: TpmPersistent(0x8100_0001),
    };
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
                &sessions,
                &mut writer,
            )
            .unwrap();
            writer.len()
        };
        buf[..len].to_vec()
    };

    let (res_handles, res_cmd_data, res_sessions) = tpm_parse_command(&generated_bytes).unwrap();

    let handles = [cmd.auth.0, cmd.object_handle.0];
    assert_eq!(res_handles.as_ref(), handles);
    assert_eq!(res_sessions, sessions);
    assert_eq!(res_cmd_data, TpmCommandBody::EvictControl(cmd));
}

fn test_command_build_evict_control() {
    let cmd = TpmEvictControlCommand {
        auth: (TpmRh::Owner as u32).into(),
        object_handle: 0x8000_0000.into(),
        persistent_handle: TpmPersistent(0x8100_0001),
    };
    let mut sessions = TpmAuthCommands::new();
    sessions
        .try_push(TpmsAuthCommand {
            session_handle: TpmSession(TpmRh::Password as u32),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::try_from(&b"123"[..]).unwrap(),
        })
        .unwrap();

    let mut buf = [0u8; 1024];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        tpm_build_command(
            &cmd,
            tpm2_protocol::data::TpmSt::Sessions,
            &sessions,
            &mut writer,
        )
        .unwrap();
        writer.len()
    };
    let generated_bytes = &buf[..len];
    let expected_bytes = hex_to_bytes(
        "8002000000260000012040000001800000000000000c40000009000000000331323381000001",
    )
    .unwrap();
    assert_eq!(generated_bytes, expected_bytes.as_slice());
}

fn test_command_build_nv_write() {
    let cmd = TpmNvWriteCommand {
        auth_handle: (TpmRh::Owner as u32).into(),
        nv_index: 0x0100_0000,
        data: Tpm2bMaxNvBuffer::try_from(&[0xDE, 0xAD, 0xBE, 0xEF][..]).unwrap(),
        offset: 0,
    };
    let mut sessions = TpmAuthCommands::new();
    sessions
        .try_push(TpmsAuthCommand {
            session_handle: TpmSession(TpmRh::Password as u32),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::try_from(&b"123"[..]).unwrap(),
        })
        .unwrap();

    let mut buf = [0u8; 1024];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        tpm_build_command(
            &cmd,
            tpm2_protocol::data::TpmSt::Sessions,
            &sessions,
            &mut writer,
        )
        .unwrap();
        writer.len()
    };
    let generated_bytes = &buf[..len];
    let expected_bytes = hex_to_bytes(
        "80020000002a0000013740000001010000000000000c4000000900000000033132330004deadbeef0000",
    )
    .unwrap();
    assert_eq!(generated_bytes, expected_bytes.as_slice());
}

fn test_macro_response_parse_correctness() {
    let mut digests = tpm2_protocol::data::TpmlDigestValues::new();
    let digest = tpm2_protocol::data::TpmtHa {
        hash_alg: TpmAlgId::Sha256,
        digest: tpm2_protocol::data::TpmuHa::Sha256([0xA1; 32]),
    };
    digests.try_push(digest).unwrap();
    let original_resp = TpmPcrEventResponse { digests };

    let mut body_buf = [0u8; 1024];
    let body_len = {
        let mut writer = TpmWriter::new(&mut body_buf);
        TpmBuild::build(&original_resp, &mut writer).unwrap();
        writer.len()
    };
    let response_body_bytes = &body_buf[..body_len];

    let expected_len = size_of::<u32>() + original_resp.digests.len();
    assert_eq!(body_len, expected_len);
    assert_eq!(
        &response_body_bytes[0..4],
        &u32::to_be_bytes(original_resp.digests.len() as u32)
    );
    assert_eq!(&response_body_bytes[4..8], &1u32.to_be_bytes());

    let result = TpmPcrEventResponse::parse(response_body_bytes);

    assert!(result.is_ok(), "Parsing failed: {result:?}");
    let (parsed_resp, tail) = result.unwrap();
    assert_eq!(parsed_resp, original_resp, "Response mismatch");
    assert!(tail.is_empty(), "Tail data");
}

fn test_tpmt_roundtrip_sym_def_xor() {
    let original_sym_def = TpmtSymDef {
        algorithm: TpmAlgId::Xor,
        key_bits: TpmuSymKeyBits::Xor(TpmAlgId::Sha256),
        mode: TpmuSymMode::Xor(TpmAlgId::Null),
    };

    let mut buf = [0u8; 1024];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        TpmBuild::build(&original_sym_def, &mut writer).unwrap();
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

fn test_tpmbuffer_try_from_slice_too_large() {
    const CAPACITY: usize = 4096;
    let data = vec![0; CAPACITY + 1];

    let result = TpmBuffer::<CAPACITY>::try_from(data.as_slice());

    assert_eq!(
        result,
        Err(TpmErrorKind::CapacityExceeded),
        "Should reject creating a TpmBuffer from a slice larger than its capacity"
    );
}

fn test_tpm2b_build_length_too_large() {
    let large_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            std::ptr::NonNull::<u8>::dangling().as_ptr(),
            u16::MAX as usize + 1,
        )
    };

    let mut out_buf = [0u8; 10];
    let mut writer = TpmWriter::new(&mut out_buf);

    let result = build_tpm2b(&mut writer, large_slice);

    assert_eq!(result, Err(TpmErrorKind::ValueTooLarge),);
}

fn test_response_parse_policy_get_digest() {
    let original_resp = TpmPolicyGetDigestResponse {
        policy_digest: Tpm2bDigest::try_from(&[0xAA; 32][..]).unwrap(),
    };
    let rc = TpmRc::try_from(TpmRcBase::Success as u32).unwrap();

    let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        tpm_build_response(&original_resp, &[], rc, &mut writer).unwrap();
        writer.len()
    };
    let response_bytes = &buf[..len];

    let body_buf = &response_bytes[10..];

    let result = TpmPolicyGetDigestResponse::parse(body_buf);
    assert!(result.is_ok(), "Parsing failed: {result:?}");
    let (parsed_resp, remainder) = result.unwrap();
    assert_eq!(
        parsed_resp, original_resp,
        "Parsed response does not match original"
    );
    assert!(
        remainder.is_empty(),
        "Response should have no trailing data"
    );
}

fn test_macro_response_parse_remainder() {
    let mut pcr_values = tpm2_protocol::data::TpmlDigest::new();
    pcr_values
        .try_push(Tpm2bDigest::try_from(&[0xAA; 32][..]).unwrap())
        .unwrap();

    let original_body = TpmPcrReadResponse {
        pcr_update_counter: 1,
        pcr_selection_out: TpmlPcrSelection::default(),
        pcr_values,
    };

    let mut valid_body_bytes = Vec::new();
    let mut writer_buf = [0u8; 1024];
    let len = {
        let mut writer = TpmWriter::new(&mut writer_buf);
        TpmBuild::build(&original_body, &mut writer).unwrap();
        writer.len()
    };
    valid_body_bytes.extend_from_slice(&writer_buf[..len]);

    let trailing_data = [0xDE, 0xAD, 0xBE, 0xEF];
    let mut malformed_body_with_trailer = valid_body_bytes;
    malformed_body_with_trailer.extend_from_slice(&trailing_data);

    let result = TpmPcrReadResponse::parse(&malformed_body_with_trailer);
    match result {
        Ok((parsed_body, remainder)) => {
            assert_eq!(
                parsed_body, original_body,
                "Parsed body does not match original"
            );
            assert_eq!(
                remainder, &trailing_data,
                "Remainder does not match trailing data"
            );
        }
        Err(e) => {
            panic!("Parsing failed: {e:?}");
        }
    }
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

macro_rules! test_suite {
    ($($test_fn:ident),* $(,)?) => {
        fn run_all_tests() -> usize {
            let tests: &[(&str, fn())] = &[
                $( (stringify!($test_fn), $test_fn) ),*
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
    };
}

test_suite!(
    test_command_build_evict_control,
    test_command_build_get_capability,
    test_command_build_hash,
    test_command_build_nv_write,
    test_command_parse_context_save,
    test_command_parse_evict_control,
    test_command_parse_flush_context,
    test_command_parse_get_capability,
    test_command_parse_hash,
    test_command_parse_pcr_read,
    test_dynamic_roundtrip_blind_parse,
    test_macro_response_parse_correctness,
    test_macro_response_parse_remainder,
    test_response_build_error,
    test_response_build_pcr_read,
    test_response_parse_pcr_event,
    test_response_parse_policy_get_digest,
    test_tpm2b_build_length_too_large,
    test_tpmbuffer_try_from_slice_too_large,
    test_tpm_rc_base_from_raw,
    test_tpm_rc_display,
    test_tpm_rc_index_from_raw,
    test_tpmt_roundtrip_sym_def_xor,
);

fn main() {
    let failed = run_all_tests();
    if failed > 0 {
        eprintln!("\n{failed} test(s) failed.");
        std::process::exit(1);
    }
    eprintln!("\nAll tests passed.");
}
