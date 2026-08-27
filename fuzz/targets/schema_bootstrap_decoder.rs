#![allow(unsafe_code)]
#![no_main]

use core::slice;

use sley_schema::{bootstrap_preimage, import_bootstrap_preimage};

const MAX_FUZZ_INPUT_BYTES: usize = 2048;

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
    if input.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let Ok((epoch_id, record)) = import_bootstrap_preimage(input) else {
        return;
    };
    let record_bytes = record
        .canonical_bytes()
        .expect("an imported schema epoch must remain canonical");
    let encoded = bootstrap_preimage(&record_bytes)
        .expect("an imported schema epoch must re-encode within bootstrap limits");
    assert_eq!(encoded, input, "schema bootstrap re-encoded differently");
    assert_eq!(
        record
            .schema_epoch_id()
            .expect("an imported schema epoch must retain a valid identity"),
        epoch_id,
        "schema epoch identity drifted"
    );
}
