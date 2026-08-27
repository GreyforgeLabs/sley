#![allow(unsafe_code)]
#![no_main]

use core::slice;

use sley_scb1::{
    FixtureContract, Schema, decode_payload_exact, decode_standalone_fixture,
    encode_standalone_fixture,
};

const MAX_FUZZ_INPUT_BYTES: usize = 4096;
const SELECTOR_COUNT: u8 = 18;

#[unsafe(no_mangle)]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, len: usize) -> i32 {
    if len == 0 {
        return 0;
    }
    let input = unsafe { slice::from_raw_parts(data, len) };
    fuzz_one(input);
    0
}

fn fuzz_one(input: &[u8]) {
    let Some((&selector, payload)) = input.split_first() else {
        return;
    };
    if payload.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    match selector % SELECTOR_COUNT {
        0 => decode_standalone(payload, FixtureContract::EmptyObject),
        1 => decode_standalone(payload, FixtureContract::RequiredBool),
        2 => decode_payload(&Schema::UInt(64), payload),
        3 => decode_payload(&Schema::UInt(8), payload),
        4 => decode_payload(&Schema::SInt(64), payload),
        5 => decode_payload(&Schema::Bool, payload),
        6 => decode_payload(&Schema::Bytes, payload),
        7 => decode_payload(&Schema::Text, payload),
        8 => decode_payload(&Schema::NormalizedLabel, payload),
        9 => decode_payload(&Schema::F32, payload),
        10 => decode_payload(&Schema::F64, payload),
        11 => decode_payload(&Schema::ListUInt64, payload),
        12 => decode_payload(&Schema::MapUInt8UInt8, payload),
        13 => decode_payload(&Schema::MapUInt64Text, payload),
        14 => decode_payload(&Schema::OptionUInt64, payload),
        15 => decode_payload(&Schema::UnionBool(7), payload),
        16 => decode_payload(&Schema::FixtureRecord, payload),
        17 => {
            decode_payload(&Schema::FixtureAcceptedRecord, payload);
            decode_payload(&Schema::FixtureExtensibleRecord, payload);
            decode_payload(&Schema::NestedListFixture, payload);
        }
        _ => unreachable!(),
    }
}

fn decode_payload(schema: &Schema, payload: &[u8]) {
    let _ = decode_payload_exact(schema, payload);
}

fn decode_standalone(payload: &[u8], contract: FixtureContract) {
    let Ok(decoded) = decode_standalone_fixture(payload, contract) else {
        return;
    };
    let (encoded, object_id) =
        encode_standalone_fixture(decoded.contract, &decoded.payload).expect("re-encode decoded");
    assert_eq!(
        encoded, payload,
        "standalone fixture re-encoded differently"
    );
    assert_eq!(object_id, decoded.object_id, "standalone ObjectId drifted");
}
