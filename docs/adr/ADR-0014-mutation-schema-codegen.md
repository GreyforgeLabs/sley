# ADR-0014: Full epoch-1 mutation descriptor code generation

Status: accepted for S20-340

## Decision

Generate immutable mutation descriptors for all eighteen SSMC1 epoch-1 entity
kinds directly from the hash-frozen canonical text manifest. Commit the
generated Rust artifact and require exact regeneration in the routine gate.

Keep executable mutation, candidates, precondition values, authority,
validation, and state changes outside S20-340.

## Rationale

Generating only the twelve entity kinds currently represented by restricted
runtime models would create a second partial schema authority and would not
reproduce the full S20-200 schema. The canonical manifest already freezes all
eighteen body records and is sufficient for descriptor generation without
claiming runtime support for the six unmodeled bodies.

A checked-in generated artifact makes review and downstream compilation
deterministic. An explicit generator plus an in-memory `--check` avoids ambient
`build.rs` discovery and prevents handwritten drift from moving into generated
code.

## Consequences

- mutation eligibility is derived from exact, documented syntactic type rules;
- generated output identifies its generator and source digest;
- the schema crate exports the exact manifest bytes and digest for consumers;
- the mutation crate remains read-only metadata and cannot mutate anything;
- complete runtime modeling, candidate construction, root/session/workspace
  authority, policy/capability judgment, validation, commit, and protocol work
  remain later blockers.
