#![allow(clippy::not_unsafe_ptr_arg_deref, unsafe_code)]
#![no_main]

use core::slice;

use sley_mutate::{
    build_candidate, decode_candidate_record, encode_candidate_record, import_candidate,
};

const MAX_FUZZ_INPUT_BYTES: usize = 1_048_576;
const SELECTOR_COUNT: u8 = 2;

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
        0 => import_and_rebuild(payload),
        1 => decode_and_reencode_record(payload),
        _ => unreachable!(),
    }
}

fn import_and_rebuild(payload: &[u8]) {
    let Ok(imported) = import_candidate(payload) else {
        return;
    };
    let rebuilt = build_candidate(&imported.record).expect("rebuild imported candidate");
    assert_eq!(rebuilt, imported, "imported candidate rebuild drifted");
}

fn decode_and_reencode_record(payload: &[u8]) {
    let Ok(record) = decode_candidate_record(payload) else {
        return;
    };
    let encoded = encode_candidate_record(&record).expect("re-encode decoded candidate record");
    assert_eq!(encoded, payload, "candidate record re-encoded differently");
}
