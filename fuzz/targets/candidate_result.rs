#![allow(clippy::not_unsafe_ptr_arg_deref, unsafe_code)]
#![no_main]

use core::slice;

use sley_id::CandidateResultId;
use sley_policy::{CandidateDecision, PhaseOutcome, import_candidate_result};

const MAX_FUZZ_INPUT_BYTES: usize = 1_048_576;

#[unsafe(no_mangle)]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, len: usize) -> i32 {
    if len == 0 {
        return 0;
    }
    let input = unsafe { slice::from_raw_parts(data, len) };
    if input.len() <= MAX_FUZZ_INPUT_BYTES {
        fuzz_one(input);
    }
    0
}

fn fuzz_one(input: &[u8]) {
    let Ok(first) = import_candidate_result(input) else {
        return;
    };
    let second = import_candidate_result(input).expect("accepted result must remain accepted");
    assert_eq!(first, second, "candidate-result import was not deterministic");
    assert_eq!(
        first.candidate_result_id,
        CandidateResultId::derive(&first.preimage),
        "candidate-result trailer did not bind its exact preimage"
    );
    assert_eq!(
        first.stored_bytes.len(),
        first.preimage.len() + 32,
        "candidate-result envelope length drifted"
    );
    assert_eq!(
        &first.stored_bytes[first.preimage.len()..],
        first.candidate_result_id.as_bytes(),
        "candidate-result trailer bytes drifted"
    );

    let record = &first.record;
    assert_eq!(record.phase_results.len(), 14);
    let mut failed = None;
    for (index, phase) in record.phase_results.iter().enumerate() {
        let expected = u32::try_from(index + 1).expect("phase index fits");
        assert_eq!(phase.phase_tag, expected);
        match phase.outcome {
            PhaseOutcome::Passed => {
                assert!(failed.is_none());
                assert!(phase.evidence_digest.is_some());
                assert!(phase.terminal_decision.is_none());
            }
            PhaseOutcome::Failed => {
                assert!(failed.replace(expected).is_none());
                assert!(phase.evidence_digest.is_some());
                assert_eq!(phase.terminal_decision, Some(record.decision));
                assert_ne!(record.decision, CandidateDecision::Valid);
            }
            PhaseOutcome::NotRun => {
                assert!(failed.is_some());
                assert!(phase.evidence_digest.is_none());
                assert!(phase.terminal_decision.is_none());
            }
        }
    }
    assert_eq!(record.decision == CandidateDecision::Valid, failed.is_none());
    assert_eq!(
        record.candidate_id.is_none(),
        record.decision == CandidateDecision::InvalidEncoding
    );
    assert_eq!(
        record.candidate_root.is_some(),
        record.decision == CandidateDecision::Valid
    );
}
