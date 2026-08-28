# S20-360 Candidate Validation Closeout

Status: **PASS - restricted executable-program-operation-free validation complete; no commit or runtime authority**

## Scope

This closeout covers the pure ordered candidate validator, closed trusted
context, complete epoch-1 entity/reference projection, canonical result codec,
independent result oracle and corpus, and candidate-result persistent fuzz
target. The success subset is explicitly executable-program-operation-free;
candidate mutation operations remain supported. An SSMC1 semantic `Operation`
entity fails phase 12 with `RESOURCE_LIMIT` and source symbol
`CANDIDATE_OPERATION_ANALYSIS_UNSUPPORTED`.

This slice does not cover complete operation semantics, mandatory
production-epoch semantic fingerprints, accepted-state writes, capability
budget consumption, atomic commit, receipts, repository refs, CAS, runtime
effects, protocol, benchmark trials, packaging, release, or publication.

## Implemented boundary

- `CandidateValidationContext` derives its own public digest from the exact
  accepted transaction/root/epoch, policy, principal, rebuilt capability
  summary, trusted time, inventory digest, tombstone digest, and effective
  ceilings. Callers cannot supply phase outcomes, roots, diagnostics, selected
  tests, or a context digest.
- `validate_candidate_bytes` runs all fourteen frozen phases in order. It
  strictly imports candidate bytes, checks closed context and freshness,
  rechecks creation identities, applies operations only to an in-memory clone,
  derives all-18-kind references and affected closure, invokes the owning
  type/CFG/effect/contract checkers, verifies policy/capability inputs without
  ledger mutation, finalizes mandatory tests, charges supported work, rebuilds
  the candidate root in memory, and renders validator-owned phase evidence.
- Present TypeDef and Function fingerprint claims are recomputed after their
  owning checker passes. Unsupported-kind claims fail closed. Absent supported
  claims remain a documented restricted-epoch allowance, not GA completion.
- Invalid candidates have one failed phase and a not-run suffix. `VALID` has
  fourteen passed phases and a candidate root. No path writes the object store,
  repository, ref graph, accepted root, policy root, or capability ledger.

## Conformance and adversarial evidence

- The codec-owned fixture generator emits sixteen accepted result vectors:
  `VALID` plus every terminal decision. `--check` proves the committed bytes
  still match the current Rust codec.
- The independent Python oracle strictly decodes the result envelope and
  thirteen-field record, then independently checks decision tags, failed
  phases, phase count, result IDs, monotonic phase shape, diagnostics, sets,
  and root/candidate presence rules.
- Four rejected mutations cover bad magic, digest corruption, trailing bytes,
  and truncation. Native result tests cover deeper phase, decision,
  diagnostic, set, root, and identity shape failures.
- The production result-import libFuzzer target starts from 25 unique seeds,
  reimports accepted bytes twice, rederives the result ID, checks trailer and
  envelope lengths, and asserts the fourteen-phase monotonic shape. The
  bounded 512-run smoke passed without a crash artifact.
- Eleven pipeline tests cover deterministic valid output, input and base-state
  immutability, invalid context, stale roots/preimages, identity/tombstones,
  graph/reference distinctions, exact semantic owner codes, fingerprint
  mismatch, policy/capability/authenticator checks, mandatory contracts/tests,
  expiry, isolation, ceilings, and unsupported operation analysis.

## Independent reviews

Ariadne reviewed all fourteen phases and found no false `VALID` path or
authority leak. Ariadne found one P1 contract mismatch: unsupported operation
analysis returned `INTERNAL_ERROR` while the frozen restricted contract
required `RESOURCE_LIMIT`. The implementation and focused assertion were
corrected, and Ariadne's targeted recheck resolved the finding.

Vulcan rechecked the earlier P3 evidence-breadth gap after corpus expansion.
The review confirmed independent coverage of all sixteen decisions and failed
phases, strict framing corruption coverage, fixture-to-code drift checking, and
no S20-700 or GA overstatement. Vulcan reported no remaining report-grade
P0-P4 finding in the bounded closeout scope.

## Validation

Validation tier: **Tier 2 subsystem handoff**

Affected subsystems: `sley-policy`, SSMC tag decoding used by the candidate
projection, mutation codecs, SCB1 independent oracle, result conformance
fixtures, persistent result fuzzing, and S20 frontier/evidence documents.

Passed checks:

```text
cargo test -p sley-policy candidate_validation -- --nocapture
cargo test -p sley-policy candidate_result -- --nocapture
cargo clippy -p sley-policy --all-targets -- -D warnings
cargo +nightly-2026-02-27 clippy --manifest-path fuzz/Cargo.toml --bin candidate_result -- -D warnings
python3 scripts/generate_candidate_result_fixtures.py --check
uv run --project oracle/scb1 --frozen python -m unittest discover -s oracle/scb1/tests -v
uv run --project oracle/scb1 --frozen sley2-scb1-oracle check-candidate-result --accepted conformance/candidate-result/v1/accepted.json --rejected conformance/candidate-result/v1/rejected.json
make candidate-result-persistent-fuzz-smoke
make quick
make core
make conformance
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The first Tier 1 attempt correctly detected stale S20-700 count assertions and
regenerated secret-scan evidence after the expanded tracked surface. Those
drifts were repaired and the complete `make quick` rerun passed.

The Tier 3 `make v2` and `make release-check` gates were not run. They remain
intentional fail-closed release boundaries for unfinished Sley 2 packages and
are not required for this subsystem development slice.

## Boundary result

Restricted S20-360 validation is complete and independently reviewed. A
`CandidateValidationOutput`, imported `CandidateResult`, or `VALID` decision is
evidence only. S20-390 is the first package allowed to recheck that evidence
and attempt an atomic durable commit with a receipt. The full Sley 2 goal,
complete S20-700, M3-M6 exits, succession proof, and GA remain incomplete.
