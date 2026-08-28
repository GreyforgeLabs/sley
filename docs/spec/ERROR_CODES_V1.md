# Error Codes v1

Status: M0 namespace draft with package-frozen sections. Numeric assignments
are not globally frozen except where an owning work package says so.

Every failure response binds protocol/schema version, phase, stable symbolic
and numeric code, typed details, safe causal IDs, retryability, mechanically
established repair affordances, and truncation. Prose is optional.

## Candidate terminal states

`VALID`, `INVALID_ENCODING`, `INVALID_SCHEMA`, `STALE_ROOT`, `STALE_ENTITY`,
`INVALID_IDENTITY`, `INVALID_GRAPH`, `UNRESOLVED_REFERENCE`, `TYPE_ERROR`,
`CONTROL_FLOW_ERROR`, `EFFECT_ERROR`, `CAPABILITY_DENIED`, `CONTRACT_ERROR`,
`RESOURCE_LIMIT`, `TEST_PLAN_ERROR`, and `INTERNAL_ERROR`.

Only `VALID` permits commit. `INTERNAL_ERROR`, unknown, incomparable, missing,
and ambiguity are failures, never success.

## Namespaces

- `SCB_*`: framing, canonical encoding, schema, epoch, digest, and limits.
- `ID_*`: identity derivation, collision, reuse, and workspace mismatch.
- `STORE_*`: immutable-object lookup, substitution, persistence, and local I/O.
- `STATE_ROOT_*`: root construction, duplicate input, and excluded-fact checks.
- `SSMC_*`: semantic-entity structure, closed tags, signatures, and limits.
- `GRAPH_*`, `TYPE_*`, `CFG_*`, `EFFECT_*`, `CONTRACT_*`: kernel judgment.
- `STALE_*`, `TXN_*`, `REF_*`, `RECOVERY_*`: transaction and durability.
- `POLICY_*`, `CAP_*`, `ADAPTER_*`: authority boundary.
- `QUERY_*`: typed request identity, snapshot binding, bounded traversal, and
  required-fact completeness.
- `SESSION_*`, `PROTOCOL_*`: bounded interface and negotiation.
- `FINGERPRINT_*`, `VALUE_HASH_*`, `IMPACT_*`: semantic projection and
  derived relationships.
- `INDEX_SNAPSHOT_*`: restricted derived-index record construction and
  bounded candidate inspection.
- `RESTRICTED_CAPSULE_*`: derived complete-query evidence projection and
  resource/invariant checks.
- `VM_LOWER_*`: validated deterministic derived-bytecode lowering.
- `TEST_PLAN_*`: canonical test-entity validation and provisional selection.
- `VM_*`, `TEST_*`: execution, cancellation, determinism, and oracle.
- `PACK_*`, `GC_*`, `MERGE_*`: repository operations.
- `MUTATION_CANDIDATE_*`: proposal-record structure and descriptor binding.

S20-170 freezes these repository-pack codes:

- `PACK_VERSION_UNSUPPORTED`
- `PACK_DIGEST_MISMATCH`
- `PACK_DIGEST_TREE_MISMATCH`
- `PACK_CANONICAL_ORDER`
- `PACK_DUPLICATE_ENTRY`
- `PACK_SCHEMA_UNSUPPORTED`
- `PACK_ROOT_INVALID`
- `PACK_OBJECT_MISSING`
- `PACK_OBJECT_UNEXPECTED`
- `PACK_OBJECT_CORRUPT`
- `PACK_RESOURCE_LIMIT`
- `PACK_COMPRESSION_UNSUPPORTED`
- `PACK_DECOMPRESSION_LIMIT` (reserved until a compressed profile exists)
- `PACK_PROFILE_UNSUPPORTED`

S20-180 freezes these garbage-collection codes:

- `GC_RESOURCE_LIMIT`
- `GC_ANCHOR_MALFORMED`
- `GC_ANCHOR_UNRESOLVED`
- `GC_ROOT_MISSING`
- `GC_ROOT_INVALID`
- `GC_DEPENDENCY_MISSING`
- `GC_OBJECT_REFERENCE_MALFORMED`
- `GC_OBJECT_MISSING`
- `GC_INVENTORY_INVALID`
- `GC_DRY_RUN_REQUIRED`
- `GC_EXCLUSIVE_LOCK_REQUIRED`
- `GC_DELETE_IO`
- `GC_REACHABILITY_VIOLATION`
- `GC_INTERNAL_INVARIANT`

Numeric ranges and exact detail schemas are frozen with their owning contract,
generated into all transports, and checked for drift. Bridges may not invent or
collapse codes.

S20-200 freezes numeric codes 20000 through 20015 for the exact `SSMC_*`
failures listed in `SSMC1.md`. Those codes cover structural schema judgment
only and never substitute for later `TYPE_*`, `CFG_*`, `EFFECT_*`,
`CONTRACT_*`, or `VM_*` results.

S20-210 freezes numeric codes 21000 through 21020 for the exact `TYPE_*`
failures listed in `TYPE_SYSTEM_V1.md`. They cover type well-formedness,
definition cycles, trait requirements, substitution, and constant/type
agreement only; they do not claim CFG, effect, contract, lowering, or runtime
judgment.

S20-220 freezes numeric codes 22000 through 22020 for the exact `GRAPH_*` and
`CFG_*` failures listed in `CFG_VALIDATION_V1.md`. They cover graph inventory,
reachability, dominance, value uses, target arguments, switch payloads, traps,
and bounded CFG work only; they preserve earlier `SSMC_*` and `TYPE_*` failures
and do not claim opcode semantics, effects, contracts, lowering, or runtime
judgment.

S20-230 freezes numeric codes 23000 through 23013 for the exact `EFFECT_*`,
`ADAPTER_*`, `CAPABILITY_*`, and `CONSTRAINT_*` failures listed in
`EFFECT_SYSTEM_V1.md`. They cover closed entity lookup, exact least effect
closure, direct-call/effect-operation typing, epoch-1 adapter effect
cardinality, static capability scope constants, contract-identity boundaries,
and bounded closure work only. Earlier type/CFG failures are preserved; these
codes do not claim protected-policy, runtime-token, adapter-execution,
contract-predicate, lowering, or VM judgment.

S20-240 freezes numeric codes 24000 through 24017 for the exact `CONTRACT_*`,
`TEST_PLAN_*`, and `CONTRACT_TEST_PLAN_*` failures listed in
`CONTRACT_TEST_PROFILE_V1.md`. They cover the restricted epoch-1 pure-function
contract/test profile and policy-incomplete deterministic selection only.
Unsupported invariants, effect/capability/resource bounds, effectful tests,
adapter replay/configuration, and observations fail closed. Runtime `TEST_*`,
protected-policy finality, predicate/test execution, resource evidence, and
reports remain later namespaces/packages.

S20-250 freezes numeric codes 25000 through 25012 for the exact
`FINGERPRINT_*`, `VALUE_HASH_*`, and `IMPACT_*` failures listed in
`FINGERPRINT_IMPACT_PROFILE_V1.md`. They cover the restricted epoch-1
TypeDef/Function projection, canonical value hashing, and exact impact edges
for modeled SSMC1 kinds 4 through 15. They do not claim a complete-root index;
kinds 1 through 3 and 16 through 18 remain unsupported until their semantic
bodies enter the Rust model.

S20-260 freezes numeric codes 26000 through 26006 for the exact `VM_LOWER_*`
failures listed in `VM_LOWERING_PROFILE_V1.md`. They cover only the restricted
epoch-1 O0 lowering profile for all five terminators and the three validated
Boolean opcodes, exact cache-profile binding, local rewrite invariants, and
resource ceilings. They do not claim semantic judgment for the other 52
opcodes, generic specialization, adapters, bytecode decoding, or execution.

S20-270 freezes numeric codes 27000 through 27005 for the exact `VM_EXEC_*`
failures listed in `VM_EXECUTION_PROFILE_V1.md`. They cover only integrated
restricted execution of S20-260 Boolean bytecode, all five terminators,
deterministic input/fuel/value/output/cancellation limits, traps, invariant
failures, and the observation digest. They do not claim the other 52 opcodes,
adapters/effects, live cancellation, or persistent S20-290 reports.

S20-280 freezes numeric codes 28000 through 28011 for the exact `ADAPTER_*`
failures listed in `REFERENCE_ADAPTER_PROFILE_V1.md`. They cover only the
restricted request-owned fixture profile: identity/ABI/effect/type boundaries,
canonical state and virtual paths, replay order, resource limits,
cancellation, and atomic in-memory mutation. Exact earlier `TYPE_*` and
`FINGERPRINT_*` failures are preserved. These codes do not claim VM adapter
opcode execution, protected capability judgment, or confined live host access.

S20-290 freezes numeric codes 29000 through 29007 for the exact `REPORT_*` and
`TEST_REPORT_*` failures listed in `REPORT_ENVELOPE_PROFILE_V1.md`. They cover
only deterministic derived-envelope profile/context/cache/observation/plan/
execution/resource consistency. Exact earlier `TYPE_*`, `FINGERPRINT_*`, and
`VM_LOWER_*` failures are preserved. These codes do not claim canonical report
entity validity, persistence, protected-policy finality, complete resource
evidence, a passed TestCase, or the M2 exit.

S20-300 restricted freezes numeric codes 30000 through 30007 for the exact
`INDEX_SNAPSHOT_*` failures listed in `INDEX_SNAPSHOT_PROFILE_V1.md`. They
cover bounded construction and private inspection of disposable `SLEYIDX1`
records for explicit modeled SSMC1 kinds 4 through 15. Candidate admission
always performs a fresh S20-250 rebuild before candidate inspection and
requires exact byte comparison before a hit; these codes do not establish root
provenance, authorize decoded cache edges, model
the six missing entity bodies, provide a useful performance cache, complete
full S20-300, or unblock root-backed S20-310.

S20-310 restricted freezes numeric codes 31000 through 31007 for the exact
`QUERY_*` failures listed in `RESTRICTED_QUERY_PROFILE_V1.md`. They cover four
typed modeled-snapshot queries, exact `QueryId`/context/limit binding, hard
traversal and response ceilings, and explicit failure when an applied limit
would omit a required fact. They return no partial payload and do not implement
the nineteen root-backed query classes, truncation, continuation, capsules,
SMP1, full S20-310, the M3 blocker, or GA.

S20-320 restricted freezes numeric codes 32000 through 32007 for the exact
`RESTRICTED_CAPSULE_*` failures listed in
`RESTRICTED_QUERY_CAPSULE_PROFILE_V1.md`. They cover derived dictionaries,
direct-edge indexes, source-response binding, fixed complete/nontruncated/
noncontinuable status, and bounded record construction only. They do not
implement the master context capsule, use `ContextCapsuleId`, establish
workspace/root/session provenance, authorize continuation/import, or unblock
S20-330, S20-400, S20-620, M3, M5, or GA.

S20-350 freezes numeric codes 35000 through 35010 for candidate-specific
proposal-construction failures:

| Numeric | Symbolic |
|---:|---|
| 35000 | `MUTATION_CANDIDATE_FORMAT_VERSION` |
| 35001 | `MUTATION_CANDIDATE_EXPIRY_INVALID` |
| 35002 | `MUTATION_CANDIDATE_EMPTY_OPERATIONS` |
| 35003 | `MUTATION_CANDIDATE_OPERATION_ORDINAL` |
| 35004 | `MUTATION_CANDIDATE_OPERATION_PRECONDITION_ORDINAL` |
| 35005 | `MUTATION_CANDIDATE_PRECONDITION_COUNT` |
| 35006 | `MUTATION_CANDIDATE_PRECONDITION_MISMATCH` |
| 35007 | `MUTATION_CANDIDATE_DESCRIPTOR_UNKNOWN` |
| 35008 | `MUTATION_CANDIDATE_PAYLOAD_KIND` |
| 35009 | `MUTATION_CANDIDATE_TARGET_ENTITY` |
| 35010 | `MUTATION_CANDIDATE_VALIDATION_PROFILE` |

These codes cover canonical proposal structure only. Strict encoding,
canonicality, envelope, digest, and resource failures preserve their exact
`SCB_*` code instead of being collapsed into this range. Neither namespace
claims semantic validity, authority, freshness against trusted host time, or
permission to mutate accepted state.

S20-370 freezes numeric codes 37000 through 37018 for the exact `POLICY_*`
failures listed in `POLICY_ROOT_V1.md`. They cover protected policy-record
construction/import, closed principal grant data, ordinary-program isolation,
and policy-required test/contract finalization. Exact `SCB_*` and `SCHEMA_*`
failures are preserved. These codes do not authenticate policy transitions,
issue capability tokens, establish live scope/expiry/replay/budget authority,
construct candidates, commit state, or complete M3/M4/GA.

Every validation phase has one declared default terminal state and a finite
set of more specific codes in that namespace. Retryability is an enum
(`NEVER`, `AFTER_REQUERY`, `AFTER_CAPABILITY`, `AFTER_LIMIT_CHANGE`,
`TRANSIENT_HOST`) rather than inferred prose. Truncation is explicit and never
removes the terminal code or phase. Unsupported methods, effects, epochs, or
features use versioned `*_UNSUPPORTED` failures, never generic success.

`INTERNAL_ERROR` is fail-closed, non-committable, and non-retryable unless the
typed details establish `TRANSIENT_HOST`. It carries an incident digest, not a
substitute program result. A ref comparison after any internal failure must
prove that accepted state did not advance.
