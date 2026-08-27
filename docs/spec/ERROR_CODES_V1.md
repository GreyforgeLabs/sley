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
- `QUERY_*`, `SESSION_*`, `PROTOCOL_*`: bounded interface and negotiation.
- `VM_*`, `TEST_*`: execution, cancellation, determinism, and oracle.
- `PACK_*`, `GC_*`, `MERGE_*`: repository operations.

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
