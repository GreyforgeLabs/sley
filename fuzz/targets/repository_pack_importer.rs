#![allow(unsafe_code)]
#![no_main]

use core::slice;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sley_id::{ObjectId, RepositoryPackId};
use sley_repo::import_conformance_pack;
use sley_scb1::{FixtureContract, ScbError, decode_standalone_fixture};
use sley_store::ObjectStore;

const DIGEST_TRAILER_BYTES: usize = 32;
const MAX_FUZZ_INPUT_BYTES: usize = 65_536;
const SELECTOR_COUNT: u8 = 2;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
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

    let rewritten;
    let candidate = if selector % SELECTOR_COUNT == 1 && payload.len() >= DIGEST_TRAILER_BYTES {
        rewritten = with_rehashed_pack_trailer(payload);
        rewritten.as_slice()
    } else {
        payload
    };

    let Some(temp) = TempRoot::new() else {
        return;
    };
    let store = ObjectStore::new(&temp.path);
    match import_conformance_pack(&store, candidate, &verify_fixture_object) {
        Ok(first) => {
            let preimage_len = candidate
                .len()
                .checked_sub(DIGEST_TRAILER_BYTES)
                .expect("an accepted pack must include its digest trailer");
            assert_eq!(
                first.pack_id,
                RepositoryPackId::derive(&candidate[..preimage_len]),
                "accepted repository pack identity drifted"
            );
            assert_eq!(
                first.present_objects, 0,
                "a clean import unexpectedly found existing objects"
            );

            let second = import_conformance_pack(&store, candidate, &verify_fixture_object)
                .expect("an accepted repository pack must import idempotently");
            assert_eq!(
                second.pack_id, first.pack_id,
                "repeat pack identity drifted"
            );
            assert_eq!(second.roots, first.roots, "repeat pack roots drifted");
            assert_eq!(
                second.promoted_objects, 0,
                "an idempotent import promoted an object twice"
            );
            assert_eq!(
                second.present_objects, first.promoted_objects,
                "repeat pack object accounting drifted"
            );
        }
        Err(_) => assert!(
            !store.root().join("objects").exists(),
            "failed repository pack preflight promoted object state"
        ),
    }
}

fn with_rehashed_pack_trailer(input: &[u8]) -> Vec<u8> {
    let preimage_len = input.len() - DIGEST_TRAILER_BYTES;
    let pack_id = RepositoryPackId::derive(&input[..preimage_len]);
    let mut rewritten = input.to_vec();
    rewritten[preimage_len..].copy_from_slice(pack_id.as_bytes());
    rewritten
}

fn verify_fixture_object(record: &[u8]) -> Result<ObjectId, ScbError> {
    decode_standalone_fixture(record, FixtureContract::EmptyObject)
        .or_else(|_| decode_standalone_fixture(record, FixtureContract::RequiredBool))
        .map(|fixture| fixture.object_id)
}

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new() -> Option<Self> {
        for _ in 0..1024 {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sley2-pack-persistent-fuzz-{}-{counter}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Some(Self { path }),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(_) => return None,
            }
        }
        None
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
