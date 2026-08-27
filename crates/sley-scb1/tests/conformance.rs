#![allow(missing_docs)]

use std::fmt::Write as _;

use sley_scb1::{
    FixtureContract, ScbErrorCode, Schema, UNICODE_VERSION, decode_payload_exact,
    decode_standalone_fixture, encode_bool, encode_bytes, encode_f32_bits, encode_f64_bits,
    encode_list, encode_map, encode_normalized_label, encode_option_uvar, encode_record,
    encode_sint64, encode_standalone_fixture, encode_text, encode_union, encode_uvar,
};

#[derive(serde::Deserialize)]
struct Accepted {
    vectors: Vec<AcceptedVector>,
}

#[derive(serde::Deserialize)]
struct AcceptedVector {
    id: String,
    kind: String,
    #[serde(default)]
    value: serde_json::Value,
    tag: Option<u32>,
    payload_hex: Option<String>,
    expected_hex: String,
    expected_object_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct Rejected {
    vectors: Vec<RejectedVector>,
}

#[derive(serde::Deserialize)]
struct RejectedVector {
    id: String,
    declared_type: String,
    input_hex: String,
    expected_code: String,
}

#[test]
fn accepted_vectors_match_frozen_hex() {
    let accepted: Accepted =
        serde_json::from_str(include_str!("../../../conformance/scb1/v1/accepted.json")).unwrap();
    assert_eq!(accepted.vectors.len(), 23);

    for vector in accepted.vectors {
        let actual = encode_accepted(&vector);
        assert_eq!(to_hex(&actual), vector.expected_hex, "{}", vector.id);
        decode_accepted(&vector, &actual)
            .unwrap_or_else(|error| panic!("{} rejected accepted bytes with {error}", vector.id));
    }
}

#[test]
fn epoch_invariants_and_encoder_canonicalization_hold() {
    assert_eq!(UNICODE_VERSION, (16, 0, 0));

    let overflow = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
    let error = decode_payload_exact(&Schema::UInt(64), &overflow).unwrap_err();
    assert_eq!(error.code(), ScbErrorCode::IntegerOverflow);

    let record = encode_record(&[(3, encode_uvar(300)), (1, encode_bool(true))]).unwrap();
    assert_eq!(to_hex(record), "020101010302ac02");
    let duplicate = encode_record(&[(1, vec![]), (1, vec![])]).unwrap_err();
    assert_eq!(duplicate.code(), ScbErrorCode::FieldDuplicate);

    let map = encode_map(&[
        (encode_uvar(2), encode_uvar(20)),
        (encode_uvar(1), encode_uvar(10)),
    ])
    .unwrap();
    assert_eq!(to_hex(map), "020101010a01020114");
    let duplicate = encode_map(&[(vec![1], vec![10]), (vec![1], vec![20])]).unwrap_err();
    assert_eq!(duplicate.code(), ScbErrorCode::MapDuplicate);
}

#[test]
fn rejected_vectors_return_frozen_codes() {
    let rejected: Rejected =
        serde_json::from_str(include_str!("../../../conformance/scb1/v1/rejected.json")).unwrap();
    assert_eq!(rejected.vectors.len(), 26);

    for vector in rejected.vectors {
        let input = from_hex(&vector.input_hex);
        let actual = decode_rejected(&vector.declared_type, &input)
            .expect_err("rejected vector decoded successfully")
            .code();
        assert_eq!(actual.as_str(), vector.expected_code, "{}", vector.id);
    }
}

fn encode_accepted(vector: &AcceptedVector) -> Vec<u8> {
    match vector.kind.as_str() {
        "uvar" => encode_uvar(vector.value.as_u64().unwrap()),
        "sint64" => encode_sint64(vector.value.as_i64().unwrap()),
        "bool" => encode_bool(vector.value.as_bool().unwrap()),
        "bytes_utf8_fixture" => encode_bytes(vector.value.as_str().unwrap().as_bytes()).unwrap(),
        "text" => encode_text(vector.value.as_str().unwrap()).unwrap(),
        "normalized_label" => encode_normalized_label(vector.value.as_str().unwrap()).unwrap(),
        "raw_hex" => {
            let bytes = from_hex(vector.value.as_str().unwrap());
            match bytes.len() {
                4 => encode_f32_bits(u32::from_be_bytes(bytes.try_into().unwrap())).unwrap(),
                8 => encode_f64_bits(u64::from_be_bytes(bytes.try_into().unwrap())).unwrap(),
                _ => unreachable!(),
            }
        }
        "list_uvar" => {
            let elements = vector
                .value
                .as_array()
                .unwrap()
                .iter()
                .map(|value| encode_uvar(value.as_u64().unwrap()))
                .collect::<Vec<_>>();
            encode_list(&elements).unwrap()
        }
        "record_bool_uvar" => {
            let object = vector.value.as_object().unwrap();
            let fields = vec![
                (1, encode_bool(object["1"].as_bool().unwrap())),
                (3, encode_uvar(object["3"].as_u64().unwrap())),
            ];
            encode_record(&fields).unwrap()
        }
        "map_uvar_text" => {
            let entries = vector
                .value
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| {
                    let entry = entry.as_array().unwrap();
                    (
                        encode_uvar(entry[0].as_u64().unwrap()),
                        encode_text(entry[1].as_str().unwrap()).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            encode_map(&entries).unwrap()
        }
        "option_uvar" => encode_option_uvar(vector.value.as_u64()).unwrap(),
        "union_bool" => encode_union(
            vector.tag.unwrap(),
            &encode_bool(vector.value.as_bool().unwrap()),
        )
        .unwrap(),
        "standalone_fixture_object" => {
            let payload = from_hex(vector.payload_hex.as_deref().unwrap());
            let (stored, object_id) =
                encode_standalone_fixture(FixtureContract::EmptyObject, &payload).unwrap();
            assert_eq!(
                to_hex(object_id.as_bytes()),
                vector.expected_object_id.as_deref().unwrap()
            );
            stored
        }
        kind => panic!("unknown accepted kind {kind}"),
    }
}

fn decode_accepted(vector: &AcceptedVector, input: &[u8]) -> Result<(), sley_scb1::ScbError> {
    let schema = match vector.kind.as_str() {
        "uvar" => Schema::UInt(64),
        "sint64" => Schema::SInt(64),
        "bool" => Schema::Bool,
        "bytes_utf8_fixture" => Schema::Bytes,
        "text" => Schema::Text,
        "normalized_label" => Schema::NormalizedLabel,
        "raw_hex" if input.len() == 4 => Schema::F32,
        "raw_hex" if input.len() == 8 => Schema::F64,
        "list_uvar" => Schema::ListUInt64,
        "record_bool_uvar" => Schema::FixtureAcceptedRecord,
        "map_uvar_text" => Schema::MapUInt64Text,
        "option_uvar" => Schema::OptionUInt64,
        "union_bool" => Schema::UnionBool(vector.tag.unwrap()),
        "standalone_fixture_object" => {
            return decode_standalone_fixture(input, FixtureContract::EmptyObject).map(drop);
        }
        kind => panic!("unknown accepted kind {kind}"),
    };
    decode_payload_exact(&schema, input)
}

fn decode_rejected(declared_type: &str, input: &[u8]) -> Result<(), sley_scb1::ScbError> {
    match declared_type {
        "FixtureEmptyObject" => {
            decode_standalone_fixture(input, FixtureContract::EmptyObject).map(drop)
        }
        "FixtureRequiredBool" => {
            decode_standalone_fixture(input, FixtureContract::RequiredBool).map(drop)
        }
        "UInt64" => decode_payload_exact(&Schema::UInt(64), input),
        "UInt8" => decode_payload_exact(&Schema::UInt(8), input),
        "Bool" => decode_payload_exact(&Schema::Bool, input),
        "Text" => decode_payload_exact(&Schema::Text, input),
        "NormalizedLabel" => decode_payload_exact(&Schema::NormalizedLabel, input),
        "F32" => decode_payload_exact(&Schema::F32, input),
        "F64" => decode_payload_exact(&Schema::F64, input),
        "List<UInt64>" => decode_payload_exact(&Schema::ListUInt64, input),
        "FixtureRecord" => decode_payload_exact(&Schema::FixtureRecord, input),
        "Option<UInt64>" => decode_payload_exact(&Schema::OptionUInt64, input),
        "Map<UInt8,UInt8>" => decode_payload_exact(&Schema::MapUInt8UInt8, input),
        "FixtureExtensibleRecord" => decode_payload_exact(&Schema::FixtureExtensibleRecord, input),
        "NestedListFixture" => decode_payload_exact(&Schema::NestedListFixture, input),
        _ => Err(sley_scb1::ScbError::new(ScbErrorCode::ContractUnknown)),
    }
}

fn from_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}

fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").unwrap();
        out
    })
}
