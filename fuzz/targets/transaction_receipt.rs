#![allow(clippy::not_unsafe_ptr_arg_deref, unsafe_code)]
#![no_main]

use core::slice;

use sley_id::{ReceiptId, TransactionId};
use sley_txn::{TransactionKind, import_transaction, import_transaction_receipt};

const MAX_FUZZ_INPUT_BYTES: usize = 1_048_576;

#[unsafe(no_mangle)]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, len: usize) -> i32 {
    if len == 0 {
        return 0;
    }
    let input = unsafe { slice::from_raw_parts(data, len) };
    if input.len() <= MAX_FUZZ_INPUT_BYTES {
        fuzz_transaction(input);
        fuzz_receipt(input);
    }
    0
}

fn fuzz_transaction(input: &[u8]) {
    let Ok(first) = import_transaction(input) else {
        return;
    };
    let second = import_transaction(input).expect("accepted transaction must remain accepted");
    assert_eq!(first, second, "transaction import was not deterministic");
    assert_eq!(
        first.transaction_id,
        TransactionId::derive(&first.preimage),
        "transaction identity did not bind its exact preimage"
    );
    assert_eq!(first.stored_bytes, input);
    assert_eq!(first.stored_bytes.len(), first.preimage.len() + 32);
    assert_eq!(
        &first.stored_bytes[first.preimage.len()..],
        first.transaction_id.as_bytes()
    );
    assert_eq!(
        first.record.parent_transaction_ids.len(),
        first.record.parent_roots.len()
    );
    assert!(first.record.selected_tests.is_empty());
    assert!(first.record.test_result_refs.is_empty());
}

fn fuzz_receipt(input: &[u8]) {
    let Ok(first) = import_transaction_receipt(input) else {
        return;
    };
    let second =
        import_transaction_receipt(input).expect("accepted receipt must remain accepted");
    assert_eq!(first, second, "receipt import was not deterministic");
    assert_eq!(
        first.receipt_id,
        ReceiptId::derive(&first.preimage),
        "receipt identity did not bind its exact preimage"
    );
    assert_eq!(first.stored_bytes, input);
    assert_eq!(first.stored_bytes.len(), first.preimage.len() + 32);
    assert_eq!(
        &first.stored_bytes[first.preimage.len()..],
        first.receipt_id.as_bytes()
    );
    assert_eq!(first.record.transaction_id, first.transaction.transaction_id);
    assert_eq!(first.record.stored_transaction, first.transaction.stored_bytes);
    assert_eq!(first.transaction.record.committed_root, first.state_root.root);
    assert_eq!(
        first.transaction.record.policy_root_id,
        first.policy_root.root()
    );
    match first.transaction.record.transaction_kind {
        TransactionKind::TrustedGenesis => {
            assert!(first.candidate.is_none());
            assert!(first.candidate_result.is_none());
        }
        TransactionKind::OrdinaryCandidate => {
            assert!(first.candidate.is_some());
            assert!(first.candidate_result.is_some());
        }
    }
}
