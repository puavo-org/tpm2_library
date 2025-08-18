// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use rand::Rng;
use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug;
use tpm2_protocol::{
    data::{TpmAlgId, TpmaSession, TpmsClockInfo},
    TpmBuild, TpmErrorKind, TpmParse, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

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

fn random_object(rng: &mut impl Rng) -> (TypeId, Box<dyn TpmObject>) {
    match rng.gen_range(0..3) {
        0 => (
            TypeId::Clock,
            Box::new(TpmsClockInfo {
                clock: rng.gen(),
                reset_count: rng.gen(),
                restart_count: rng.gen(),
                safe: (rng.gen::<u8>() % 2 == 0).into(),
            }),
        ),
        1 => {
            let alg = loop {
                if let Ok(alg) = TpmAlgId::try_from(rng.gen::<u16>()) {
                    break alg;
                }
            };
            (TypeId::Alg, Box::new(alg))
        }
        _ => (
            TypeId::SessionAttrs,
            Box::new(TpmaSession::from_bits_truncate(rng.gen())),
        ),
    }
}

#[test]
fn test_dynamic_roundtrip_blind_parse() -> Result<(), TpmErrorKind> {
    let mut parsers: HashMap<TypeId, ObjectParser> = HashMap::new();
    parsers.insert(TypeId::Clock, make_parser::<TpmsClockInfo>());
    parsers.insert(TypeId::Alg, make_parser::<TpmAlgId>());
    parsers.insert(TypeId::SessionAttrs, make_parser::<TpmaSession>());

    const LIST_SIZE: usize = 100;
    let mut rng = rand::thread_rng();
    let (type_list, original_list): (Vec<_>, Vec<_>) =
        (0..LIST_SIZE).map(|_| random_object(&mut rng)).unzip();
    let mut byte_stream = [0u8; TPM_MAX_COMMAND_SIZE];
    let final_len = {
        let mut writer = TpmWriter::new(&mut byte_stream);
        for i in 0..LIST_SIZE {
            let type_id = type_list[i];
            let item = &original_list[i];
            TpmBuild::build(&(type_id as u8), &mut writer)?;
            item.build(&mut writer)?;
        }
        writer.len()
    };
    let written_bytes = &byte_stream[..final_len];

    let mut parsed_list: Vec<Box<dyn TpmObject>> = Vec::with_capacity(LIST_SIZE);
    let mut remaining_bytes = written_bytes;

    while !remaining_bytes.is_empty() {
        let (tag_byte, stream_after_tag) = u8::parse(remaining_bytes)?;
        let type_id = TypeId::try_from(tag_byte)?;

        let parser_fn = parsers.get(&type_id).expect("Parser not registered!");

        let (parsed_obj, next_bytes) = parser_fn(stream_after_tag)?;
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
    Ok(())
}
