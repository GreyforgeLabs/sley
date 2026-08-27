# Error Codes v1

Status: M0 normative draft; numeric assignments are not frozen.

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
- `GRAPH_*`, `TYPE_*`, `CFG_*`, `EFFECT_*`, `CONTRACT_*`: kernel judgment.
- `STALE_*`, `TXN_*`, `REF_*`, `RECOVERY_*`: transaction and durability.
- `POLICY_*`, `CAP_*`, `ADAPTER_*`: authority boundary.
- `QUERY_*`, `SESSION_*`, `PROTOCOL_*`: bounded interface and negotiation.
- `VM_*`, `TEST_*`: execution, cancellation, determinism, and oracle.
- `PACK_*`, `GC_*`, `MERGE_*`: repository operations.

Numeric ranges and exact detail schemas are frozen with their owning contract,
generated into all transports, and checked for drift. Bridges may not invent or
collapse codes.

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
