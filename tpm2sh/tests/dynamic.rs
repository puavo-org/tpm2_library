use rand::Rng;
use tpm2_protocol::{
    data::{TpmAlgId, TpmaSession, TpmsClockInfo},
    TpmErrorKind, TpmObject, TpmParse, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

#[derive(Debug, PartialEq, Clone)]
enum TypeId {
    Clock,
    Alg,
    SessionAttrs,
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
fn test_dynamic_roundtrip() -> Result<(), TpmErrorKind> {
    const LIST_SIZE: usize = 100;
    let mut rng = rand::thread_rng();

    let (type_list, original_list): (Vec<_>, Vec<_>) =
        (0..LIST_SIZE).map(|_| random_object(&mut rng)).unzip();

    let mut byte_stream = [0u8; TPM_MAX_COMMAND_SIZE];
    let final_len = {
        let mut writer = TpmWriter::new(&mut byte_stream);
        for item in &original_list {
            item.build(&mut writer)?;
        }
        writer.len()
    };
    let written_bytes = &byte_stream[..final_len];

    let mut parsed_list: Vec<Box<dyn TpmObject>> = Vec::with_capacity(LIST_SIZE);
    let mut remaining_bytes = written_bytes;

    for type_id in &type_list {
        let (parsed_obj, next_bytes) = match type_id {
            TypeId::Clock => {
                let (obj, remainder) = TpmsClockInfo::parse(remaining_bytes)?;
                (Box::new(obj) as Box<dyn TpmObject>, remainder)
            }
            TypeId::Alg => {
                let (obj, remainder) = TpmAlgId::parse(remaining_bytes)?;
                (Box::new(obj) as Box<dyn TpmObject>, remainder)
            }
            TypeId::SessionAttrs => {
                let (obj, remainder) = TpmaSession::parse(remaining_bytes)?;
                (Box::new(obj) as Box<dyn TpmObject>, remainder)
            }
        };
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
            "Parsed object at index {i} does not match the original."
        );
    }

    Ok(())
}
