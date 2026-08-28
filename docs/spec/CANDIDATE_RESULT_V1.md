# Candidate Result and Validation Pipeline v1

Status: S20-360 normative contract implemented for the operation-free
restricted conformance epoch. Full-GA operation analysis and S20-390 commit
remain separate incomplete packages.

## 1. Boundary and authority

Candidate validation is a deterministic, read-only judgment over one stored
candidate and one explicit trusted context. Candidate fields are comparison
targets, not authority. Validation never mutates the accepted root, object
store, repository, ref, transaction graph, capability ledger, policy root,
candidate bytes, or host state.

A `CandidateResult` is immutable evidence. Its digest proves exact result
bytes, not authorization to commit. Only a `VALID` result is eligible for the
separate S20-390 commit recheck, and no S20-360 API performs that recheck or a
durable action.

The implementation may validate the explicitly supported conformance-epoch
semantic subset. Any unimplemented semantic, capability, resource, object, or
root judgment fails closed; it cannot produce `VALID`.

## 2. Trusted validation context

The host supplies one closed validation context containing:

- exact accepted base `TransactionId` and registry-authorized
  `AcceptedStateRoot`;
- the complete strictly decoded SSMC1 entity-object inventory whose IDs equal
  every base-root binding, with no missing or surplus object;
- a canonical set of tombstoned `EntityId` values;
- the exact accepted schema epoch and decoder set;
- the registry-authorized `AcceptedPolicyRoot`;
- the authenticated `PrincipalId`;
- capability tokens plus explicit trusted issuer/key/secret facts sufficient
  to rebuild the proposal's capability summary without serializing secrets;
- explicit trusted `now_unix_millis` and local ceilings no looser than the
  schema, profile, or policy.

The context contains no caller-supplied phase outcome, semantic-pass claim,
candidate-root claim, test-plan claim, or diagnostic suppression. A
`ValidationContextDigest` is validator-owned evidence over the canonical
public projection: accepted base transaction/root, schema, policy, principal,
rebuilt capability-summary digest, trusted time, object-inventory digest,
tombstone digest, and effective ceilings. Host secrets, token authenticators,
raw token bytes, ledger memory, paths, and handles are excluded.

The canonical public projection is one exact eleven-field SCB1 Record:

| Tag | Field | Encoding |
|---:|---|---|
| 1 | context format | `UInt32`, exactly `1` |
| 2 | accepted base transaction | exact `TransactionId` bytes |
| 3 | accepted base state | exact `StateRoot` bytes |
| 4 | accepted schema epoch | exact `SchemaEpochId` bytes |
| 5 | accepted policy | exact `PolicyRootId` bytes |
| 6 | principal | exact `PrincipalId` bytes |
| 7 | rebuilt capability summary | exact `CapabilitySummaryDigest` bytes |
| 8 | trusted validation time | `UInt64` milliseconds |
| 9 | object inventory digest | exact component digest |
| 10 | tombstone digest | exact component digest |
| 11 | effective ceilings | exact nine-field limits Record |

The inventory component is a canonical List of two-field Records containing
`EntityId` and `ObjectId`, sorted by their encoded record bytes. The tombstone
component is a canonical raw-ID-sorted List of `EntityId` bytes. Their exact
digests are:

```text
inventory_digest = BLAKE3-256(
  "sley2.validation-context-inventory.v1" ||
  u64be(byte_length(canonical_inventory_list)) || canonical_inventory_list
)
tombstone_digest = BLAKE3-256(
  "sley2.validation-context-tombstones.v1" ||
  u64be(byte_length(canonical_tombstone_list)) || canonical_tombstone_list
)
```

The limits Record contains, in order, maximum operations, preconditions,
candidate bytes, decoded/change bytes, graph work, selected tests, entities,
test call depth, and test wall timeout. Values are the effective minima after
clamping requested local limits to the full-v1 profile, SCB1, policy, and
implementation hard ceilings. A looser requested limit therefore cannot alter
authority or produce a different effective context.

The exact digest wrapper is:

```text
ValidationContextDigest = BLAKE3-256(
  "sley2.validation-context.v1" ||
  u64be(byte_length(canonical_public_projection)) ||
  canonical_public_projection
)
```

This formula alone grants no context authority. The in-process validator owns
construction of the closed public projection; a caller-supplied byte string or
digest is never accepted as a phase result.

## 3. Candidate attempt and result identity

Every byte attempt has a causal digest, including malformed input:

```text
attempt_preimage = "SLEYATT1" || u64be(len(stored_candidate_bytes)) ||
                   stored_candidate_bytes
CandidateAttemptDigest =
  BLAKE3-256("sley2.candidate-attempt.v1" || attempt_preimage)
```

This digest is not a `CandidateId` and cannot stand in for one. The result's
`candidate_id` is `Some` only after exact `SLEYCAN1` envelope, trailer, record,
and structural verification. Invalid encoding therefore never fabricates a
candidate identity.

The canonical result envelope is:

```text
result_preimage = "SLEYCRS1" || uvar(1) ||
                  len(candidate_result_record) || candidate_result_record
CandidateResultId =
  BLAKE3-256("sley2.candidate-result.v1" || result_preimage)
stored_result = result_preimage || CandidateResultId[32]
```

The digest trailer is outside its own preimage and no bytes follow it.

## 4. Candidate result record

All thirteen fields are required. `Option<T>` uses SCB1 tags `0=None` and
`1=Some<T>`.

| Tag | Field | Type |
|---:|---|---|
| 1 | format_version | `UInt32`, exactly `1` |
| 2 | candidate_attempt_digest | `FixedBytes<32>` |
| 3 | candidate_id | `Option<CandidateId>` |
| 4 | validation_profile_id | exact full-v1 `ValidationProfileId` |
| 5 | validation_context_digest | `FixedBytes<32>` |
| 6 | decision | closed `CandidateDecision` |
| 7 | phase_results | exactly fourteen ordered `PhaseResult` records |
| 8 | diagnostics | ordered `List<CandidateDiagnostic>` |
| 9 | affected_closure | raw-ID-sorted `Set<EntityId>` |
| 10 | required_capabilities | raw-ID-sorted `Set<EntityId>` |
| 11 | selected_tests | raw-ID-sorted `Set<EntityId>` |
| 12 | candidate_root | `Option<StateRoot>`; `Some` iff `VALID` |
| 13 | validated_at_unix_millis | trusted explicit `UInt64` |

A candidate root is present exactly for `VALID`; every other decision carries
`None`.

For invalid encoding, fields derived from decoded candidate semantics are
empty, `candidate_id=None`, and phase 1 alone is failed. For every other
decision, `candidate_id=Some(exact verified CandidateId)`.

Each `PhaseResult` is the exact required four-field Record:

| Tag | Field | Type |
|---:|---|---|
| 1 | phase_tag | `UInt32`, exact ordinal `1..=14` |
| 2 | outcome | `PhaseOutcome` |
| 3 | evidence_digest | `Option<FixedBytes<32>>` |
| 4 | terminal_decision | `Option<CandidateDecision>` |

Each `CandidateDiagnostic` is the exact required six-field Record:

| Tag | Field | Type |
|---:|---|---|
| 1 | phase_tag | `UInt32` |
| 2 | result_code | frozen S20-360 `UInt32` |
| 3 | source_numeric_code | `Option<UInt32>` |
| 4 | source_symbol | bounded ASCII `Text` |
| 5 | retryability | `DiagnosticRetryability` |
| 6 | causal_digest | `Option<FixedBytes<32>>` |

Diagnostic retryability tags are `1=PERMANENT`, `2=FRESH_BASE`,
`3=FRESH_AUTHORITY`, `4=HIGHER_CEILINGS`, and `5=INTERNAL_REPAIR`. Source
symbols are 1 through 96 ASCII bytes, begin with `A..Z`, and contain only
`A..Z`, `0..9`, or `_`. Diagnostics are strictly ordered by their complete
typed record, contain no duplicates, and all bind the one failed phase and its
outer result code. `VALID` carries no diagnostics; every invalid decision
carries at least one primary diagnostic. The primary diagnostic is exactly
list element zero after that strict typed ordering; it has no redundant marker
field. Import derives and validates this element explicitly, so an empty list
is an omitted-primary failure.

The three entity-ID sets are strictly raw-ID ascending and duplicate-free,
with at most 65,535 members each. Invalid encoding carries empty sets. The
diagnostic list is bounded to 1,024 records.

## 5. Decision tags

Tags are closed and preserve the master-goal states:

| Tag | Decision | Failed phase |
|---:|---|---:|
| 1 | `VALID` | none |
| 2 | `INVALID_ENCODING` | 1 |
| 3 | `INVALID_SCHEMA` | 2 |
| 4 | `STALE_ROOT` | 3 |
| 5 | `STALE_ENTITY` | 3 |
| 6 | `INVALID_IDENTITY` | 4 |
| 7 | `INVALID_GRAPH` | 5 |
| 8 | `UNRESOLVED_REFERENCE` | 5 |
| 9 | `TYPE_ERROR` | 6 |
| 10 | `CONTROL_FLOW_ERROR` | 7 |
| 11 | `EFFECT_ERROR` | 8 |
| 12 | `CAPABILITY_DENIED` | 9 |
| 13 | `CONTRACT_ERROR` | 10 |
| 14 | `RESOURCE_LIMIT` | the first bounded phase that exhausted its ceiling |
| 15 | `TEST_PLAN_ERROR` | 11 |
| 16 | `INTERNAL_ERROR` | the first phase whose invariant failed closed |

`RESOURCE_LIMIT` records the actual first failed phase; it never permits a
later phase to run. Unknown decisions are invalid result bytes.

## 6. Phase records and monotonicity

The exact phase order is:

1. canonical frame;
2. schema and limits;
3. stale base and preimages;
4. identity;
5. graph and references;
6. type;
7. CFG;
8. effects;
9. protected capability and policy;
10. contracts;
11. test planning;
12. supported resource analysis;
13. candidate-root construction;
14. final candidate/result digest generation.

Each `PhaseResult` is a four-field record: `phase_tag`, `outcome`, optional
`evidence_digest`, and optional `terminal_decision`. Outcomes are `1=PASSED`,
`2=FAILED`, and `3=NOT_RUN`. Passed and failed phases carry validator-derived
evidence; not-run phases carry neither evidence nor a decision. A valid result
has fourteen passed phases. An invalid result has a passed prefix, exactly one
failed phase whose decision equals the outer decision, and a not-run suffix.

Phase evidence uses:

```text
PhaseEvidenceDigest = BLAKE3-256(
  "sley2.candidate-phase-evidence.v1" ||
  u32be(phase_tag) || uvar(byte_length(canonical_phase_input_output)) ||
  canonical_phase_input_output
)
```

Phase evidence cannot contain a caller-provided pass flag. Import validates
the monotonic shape but does not rerun or authenticate the underlying
judgment; only the in-process validator creates authoritative result objects.

For a successful phase 14, `canonical_phase_input_output` is the
validator-owned final-result core: result fields 1 through 6 and 8 through 13,
phase records 1 through 13, and phase-14 tag/outcome with its evidence and
terminal fields omitted. It excludes `CandidateResultId`, the stored result
bytes, and its own `PhaseEvidenceDigest`, preventing a self-hash cycle. The
canonical result envelope then binds that phase-14 evidence and every other
record byte. A terminal result whose earlier phase failed may still receive
its envelope integrity digest from the failure renderer; that does not mark
phase 14 as executed or passed.

## 7. Required phase judgments

- Phase 1 strictly imports candidate bytes and verifies `CandidateId`.
- Phase 2 binds the exact full-v1 profile, schema epoch, candidate and decoded
  value limits, context completeness, and effective ceilings.
- Phase 3 compares accepted transaction/root/epoch/policy/capability bindings,
  checks explicit time against candidate and policy expiry, and verifies every
  exact entity/container preimage against the base binding.
- Phase 4 rechecks deterministic creation IDs and rejects collision with live
  or tombstoned identities.
- Phase 5 applies operations only to an in-memory clone, checks operation-local
  invariants, derives the exact complete reference graph, and distinguishes
  malformed graph structure from a missing referenced identity.
- Phases 6 through 8 invoke the owning S20-210/S20-220/S20-230 checkers and
  preserve their exact source code in diagnostics.
- Present semantic-fingerprint claims on supported TypeDef and Function
  entities are recomputed only after their owning semantic checker passes.
  A mismatch is reported at phase 6 for TypeDef or phase 8 for Function while
  preserving `FINGERPRINT_MISMATCH` as the source symbol. Present claims on an
  unsupported entity kind fail closed. The restricted conformance epoch allows
  absent claims; complete production-epoch assembly must require every
  master-goal-mandatory claim before GA.
- Phase 9 independently rebuilds and compares the capability summary, verifies
  authenticated token bindings where present, enforces policy mutation-class
  grants and ceilings, and runs protected ordinary-program isolation.
- Phase 10 invokes the owning contract checker.
- Phase 11 finalizes the checker-produced plan against protected mandatory
  tests/contracts; caller-selected tests are forbidden.
- Phase 12 charges deterministic operation, decoded-value, graph, checker,
  selected-test, and candidate-object/root construction work against the
  narrowest applicable ceiling. Unsupported analysis fails closed.
- Phase 13 canonically builds every changed SSMC1 object and the candidate
  `StateRoot` in memory. The policy, schema, contract root, and test root stay
  unchanged for an ordinary candidate.
- Phase 14 derives the result from validator-owned phase evidence. It performs
  no commit, I/O, ledger charge, ref change, or accepted-state mutation.

## 8. Diagnostics and stable result codes

Diagnostics are deterministic, bounded records containing phase tag, one
S20-360 numeric/result symbol, optional preserved source numeric code, exact
source symbol, retryability tag, and optional safe causal digest. They contain
no free-form host error, secret, path, source text, model text, or unbounded
payload. Unknown or omitted primary diagnostics invalidate imported result
bytes.

Numeric codes 36000 through 36014 correspond in order to every non-`VALID`
decision listed in Section 5. Their symbols are the decision prefixed with
`CANDIDATE_VALIDATION_`, for example
`CANDIDATE_VALIDATION_INVALID_ENCODING`. Exact underlying `SCB_*`, `TYPE_*`,
`CFG_*`, `EFFECT_*`, `POLICY_*`, `CAP_*`, and `CONTRACT_*` symbols remain in
the source-code field and are never collapsed into success.

The result symbol is the unique mapping of `result_code` and is therefore not
duplicated as a second text field. Result-integrity shape failures use numeric
codes 36100 through 36107 under `CANDIDATE_RESULT_*`; strict SCB1 syntax,
canonicality, resource, envelope, and digest failures retain their exact
`SCB_*` source code.

## 9. Acceptance and explicit gaps

Acceptance requires exact result round trips and fixed vectors; all sixteen
decisions; every phase as the first failure; stale root/entity/preimage tests;
identity collision and tombstone tests; graph/reference distinction; exact
type/CFG/effect/contract source-code preservation; capability-summary,
expiry, mutation-grant, policy-isolation, and mandatory-test failures; resource
ceilings; byte-identical repeated valid results; invalid-state immutability;
and persistent fuzzing of result import and monotonic phase shape.

The landed conformance slice can produce `VALID` only when the projected SSMC1
program contains no `Operation` entities. This is an explicit supported subset,
not an inference that operation semantics are safe. Encountering an operation
fails phase 12 with `RESOURCE_LIMIT` and source symbol
`CANDIDATE_OPERATION_ANALYSIS_UNSUPPORTED`. The validator still exercises all
fourteen phases, all sixteen terminal decision encodings, complete all-18-kind
reference extraction, native type/CFG/effect/contract owners, capability and
policy checks, mandatory test planning, in-memory root reconstruction, and
byte-identical result generation for the supported subset.

S20-360 does not authorize policy transitions, mutate accepted state, consume
runtime capability budget, execute tests or effects, write objects, commit,
create receipts, move refs, perform CAS, access a repository, open a session,
invoke a provider, deploy, publish, or complete M3/M4/GA. S20-390 remains the
first package allowed to perform durable commit after an exact recheck.
