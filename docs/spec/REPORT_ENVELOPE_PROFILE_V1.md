# Restricted Report Envelope Profile v1

Status: S20-290 restricted epoch-1 normative specification.

This profile freezes deterministic derived envelopes around the evidence that
S20-240 and S20-270 can already establish. It does not add the frozen but
unmodeled SSMC `ExecutionReport` or `TestReport` entity bodies, persist an
object, create a report reference, finalize protected-policy test selection,
or claim the M2 exit.

The implementation lives in `sley-conformance`. `sley-vm` remains the only
execution/observation semantic authority; the conformance layer verifies and
projects VM evidence but never reimplements execution.

## 1. Authority and profiles

The existing identifier domains remain exact:

- `sley2.execution-report.v1` -> `ExecutionReportId`;
- `sley2.test-report.v1` -> `TestReportId`.

The restricted envelope preimages use independent inner magics `SLEYEXR1` and
`SLEYTSR1`, each with `profile_version=1`. The resulting IDs identify only
the complete derived envelope bytes described here. They are not `EntityId`,
`ObjectId`, canonical program state, a persistence receipt, policy authority,
or proof that a caller actually ran an unobserved rejected request.

The execution profile is exactly S20-270 `VM_EXEC_RESTRICTED_V1`; the VM and
lowering semantic versions are `[1,0,0]`, and the lowering/cache profile is
`CacheProfile::RESTRICTED_V1`. Other profiles fail closed.

## 2. Execution envelope input evidence

One constructor receives exact `SchemaEpochId`, `StateRoot`, Function
`EntityId`, `TypeEnvironment`, `ExecutionRequest`, and either an S20-270
`ExecutionOutcome` or `ExecutionError`.

```text
ExecutionInputEvidence =
  Validated(list(ValueHash)) |
  UnavailableBeforeValidation { submitted_count: u64 }
```

For an observed outcome, `sley-vm` reuses the exact S20-270 input boundary:
count, complete `check_constant`, `require_hashable`, exact Function parameter
type, checked aggregate input value units, and S20-250 value hashing under the
supplied schema epoch. The envelope then carries the exact ordered hashes.

For a rejected request, the constructor attempts only the same complete
constant/hashability/hash projection. If any input is unhashable, malformed,
over the hard count, wrong for its Function parameter, or over the 67,108,864
aggregate value-unit gate, it records the explicit unavailable arm and
submitted count. It does not replace or reorder the supplied `ExecutionError`, and it
does not fabricate a hash for invalid data. Distinct invalid requests may
therefore share a restricted rejection-envelope ID; this envelope is semantic
failure evidence, not an attempt nonce or audit-log identity.

The four S20-270 limits and optional cancellation point are always retained
exactly.

## 3. Stable failure evidence

Pre-execution rejection is projected without debug strings:

```text
FailurePhase = Type(1) | Cfg(2) | Lowering(3) |
               Fingerprint(4) | Execution(5)

FailureEvidence { phase: FailurePhase, numeric_code: u32 }
```

Nested preserved errors map back to their owning phase and frozen numeric
code. A Type failure inside CFG/lowering remains Type; a CFG failure inside
lowering remains CFG. The S20-220 `GRAPH_*` codes share
`FailurePhase::Cfg` with the `CFG_*` codes because both are members of the
closed `CfgErrorCode` phase; their distinct numeric codes are unchanged. No
prose, Rust layout, error-chain formatting, retry
guess, or generic unknown code enters the envelope.

## 4. Observed execution evidence

```text
ObservedTermination =
  Success(ValueHash) |
  ResourceLimit(ResourceKind) |
  Cancelled |
  Trap { trap_tag: u32, payload: Option<ValueHash> } |
  InternalInvariant

ExecutionReportResult =
  Observed {
    cache_key: BytecodeCacheKey,
    termination: ObservedTermination,
    instruction_count: u64,
    fuel_used: u64,
    peak_value_units: u64,
    observation_id: ObservationId
  } |
  Rejected(FailureEvidence)
```

For an observed result, the constructor requires exact root/epoch/function
context, derives the restricted cache key through `sley-vm`, validates and
hashes returned/trap values, and asks `sley-vm` to rederive the observation ID
from the exact input hashes, limits, cache key, termination, and counters. Any
context, cache-key, or observation mismatch fails rather than emitting a
report. The envelope links to the S20-270 `ObservationId`; it never replaces
that execution evidence anchor.

A rejected envelope records the supplied stable failure projection and has no
cache key or observation claim. Because the constructor cannot prove that an
arbitrary supplied error was produced by execution, this arm is diagnostic,
derived evidence only.

## 5. Execution report preimage

Lists use `u64be(count)||items`. Options use `u32be(1)` for none and
`u32be(2)||item` for some. Integers are big endian.

```text
execution_report_preimage =
  "SLEYEXR1" || u32be(profile_version=1) ||
  SchemaEpochId[32] || ssmc1_field_schema_hash[32] ||
  ssmc1_decoder_limits_hash[32] || StateRoot[32] || FunctionId[32] ||
  u32be(vm_major=1) || u32be(vm_minor=0) || u32be(vm_patch=0) ||
  u32be(execution_profile=1) ||
  input_evidence ||
  u64be(max_instructions) || u64be(max_fuel) ||
  u64be(max_value_units) || u64be(max_output_units) ||
  option(u64be, cancel_at_fuel) ||
  report_result

input_evidence(Validated) = u32be(1) || list(ValueHash[32])
input_evidence(Unavailable) = u32be(2) || u64be(submitted_count)

report_result(Observed) =
  u32be(1) || BytecodeCacheKey[32] || observed_termination ||
  u64be(instruction_count) || u64be(fuel_used) ||
  u64be(peak_value_units) || ObservationId[32]
report_result(Rejected) =
  u32be(2) || u32be(failure_phase) || u32be(numeric_code)

ExecutionReportId =
  BLAKE3-256("sley2.execution-report.v1" || execution_report_preimage)
```

Observed termination uses the S20-270 arm/resource tags and hashes, not raw
values. The envelope preimage is capped at 67,108,864 bytes.
Hash projection work for TestCase inputs/expected values is independently
bounded by the same 67,108,864 aggregate semantic value-unit ceiling.

## 6. Restricted test aggregation

The test constructor receives one already successful S20-240
`ContractTestReport`, the exact selected `TestCaseDefinition` bodies in
raw-ID selected order, and one verified execution envelope per selected test.

It requires:

- plan Contract, TestCase, and selected-TestCase ID lists are strictly raw-ID
  ordered and duplicate-free;
- selected IDs are a subset of the plan TestCase IDs;
- selected bodies and execution envelopes have exact one-to-one order/count;
- each execution envelope has the same root/epoch, targets the TestCase
  Function, and has validated input hashes equal to the hashes of the exact
  TestCase inputs;
- the plan finality is exactly `PolicyIncomplete`.

Expected values are completely checked/hashable and compared by exact
`ValueHash` to observed success. `ExpectedOutcome::FailureCode(1..=4)` matches
only an observed S20-270 Trap with the same frozen trap tag. Resource limit,
cancellation, internal invariant, pre-execution rejection, success of the
wrong value, or a different trap tag does not match.

```text
RestrictedComparison = Match(1) | Mismatch(2) | ExecutionRejected(3)

RestrictedTestEntry {
  test: EntityId,
  execution_report: ExecutionReportId,
  expected: Value(ValueHash) | FailureCode(u32),
  comparison: RestrictedComparison
}
```

`Match` is not `Passed`. The report's required finality is
`PolicyAndResourceIncomplete`: S20-240 selection is not protected-policy
final, and S20-270 value/output units do not establish S20-240 byte-memory,
byte-output, call-depth, or wall-time ceilings. The six TestCase resource
limits remain bound inside each canonical TestCase identity but are not
misreported as enforced evidence by this envelope.

## 7. Test report preimage

```text
test_report_preimage =
  "SLEYTSR1" || u32be(profile_version=1) ||
  SchemaEpochId[32] || ssmc1_field_schema_hash[32] ||
  ssmc1_decoder_limits_hash[32] || StateRoot[32] ||
  u32be(finality=PolicyAndResourceIncomplete=1) ||
  list(Contract_EntityId[32], plan.contracts) ||
  list(TestCase_EntityId[32], plan.tests) ||
  list(TestCase_EntityId[32], plan.selected_tests) ||
  u32be(plan.contract_assertions) || u64be(plan.work) ||
  list(restricted_test_entry, entries) ||
  u64be(match_count) || u64be(mismatch_count) ||
  u64be(rejected_count)

restricted_test_entry =
  TestCase_EntityId[32] || ExecutionReportId[32] ||
  expected_arm_and_hash_or_code || u32be(comparison)

TestReportId =
  BLAKE3-256("sley2.test-report.v1" || test_report_preimage)
```

The exact plan lists and counts are evidence, not a claim that selection was
authorized. The preimage is capped at 67,108,864 bytes. At most 65,535 entries
are accepted; checked counters and allocation bounds fail closed.

## 8. Measured and host metadata

Wall duration, timestamps, runner/host identity, process/thread facts, cache
hits, paths, locale, debug text, logs, and resource measurements not already
established by S20-270 are excluded from both deterministic types and IDs.
There is no metadata map or extension bag in restricted v1. A later measured
metadata schema must identify its units, trust source, inclusion rules, and
whether it is independently signed; it cannot silently enter these IDs.

## 9. Stable S20-290 failures

| Numeric | Symbolic code |
|---:|---|
| 29000 | `REPORT_PROFILE_UNSUPPORTED` |
| 29001 | `REPORT_CONTEXT_MISMATCH` |
| 29002 | `REPORT_CACHE_KEY_MISMATCH` |
| 29003 | `REPORT_OBSERVATION_MISMATCH` |
| 29004 | `TEST_REPORT_PLAN_INVALID` |
| 29005 | `TEST_REPORT_EXECUTION_MISMATCH` |
| 29006 | `REPORT_RESOURCE_LIMIT` |
| 29007 | `REPORT_INTERNAL_INVARIANT` |

Exact earlier `TYPE_*`, `FINGERPRINT_*`, and `VM_LOWER_*` errors are preserved
when report verification invokes their owning authorities.

## 10. Acceptance and explicit gaps

- fixed vectors freeze one observed and one rejected execution envelope and
  one restricted test envelope;
- context/cache/observation/input-order/plan-order/report-order perturbations
  fail or change the exact ID;
- malformed values preserve exact earlier errors and no invalid hash is
  invented;
- success/trap match plus value/trap/rejection mismatch matrices are exact;
- at least 128 repeated equivalent report constructions produce equal bytes,
  IDs, entries, and counts;
- no host/clock/filesystem/environment/process/network metadata is read;
- strict lint and independent review have no open P0/P1/P2.

Full S20-290 GA and the M2 exit remain blocked on canonical report entity body
schemas, SCB1 object/persistence/reference rules, protected S20-370 test
selection, compatible enforcement/evidence for all TestCase resource units,
expected-observation semantics, effect/capability/adapter/replay evidence,
complete VM execution, measured metadata provenance, and independent report
conformance. Restricted envelope IDs cannot authorize commit, promotion,
release, or a claim that a TestCase passed.
