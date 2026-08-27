# Mutation and Transaction Model

Status: S20-340 immutable mutation-schema generation and S20-345 candidate
contract/identity freeze complete; S20-350 through S20-390 have no
implementation.

The refined DAG makes the complete validator depend on protected policy and
capability work. S20-340 through S20-390 must prove exact preimages, monotonic
phases, invalid-state immutability, durability, and CAS receipts.

S20-340 now generates descriptor-only Rust data from the exact frozen SSMC1
epoch-1 manifest. The committed artifact covers all eighteen entity kinds,
seventy-five body fields, all sixteen primitive mutation classes, and 179
concrete class/kind/field affordances. Its source BLAKE3-256 is
`044d21d328e40d517fd09fd099c9697fbba2c95d0a519eade333c1140d648e73`.
The generator applies only the explicit syntactic eligibility rules frozen in
`docs/spec/MUTATION_SCHEMA_V1.md`, and the routine gate requires exact
regeneration.

This is metadata, not mutation authority. There is no operation-value decoder,
candidate builder, precondition evaluator, mutation applier, repository write,
workspace/root/session authority, policy/capability judgment, transaction,
receipt, or CAS surface. S20-350 must construct actual fully bound candidates;
S20-360 through S20-390 remain required before M3/M4 or accepted-state changes.

S20-350 is explicitly deferred after architecture review. Hashing caller claims
for workspace, roots, principal, capability summary, and expiry would be
possible, but would not make a candidate schema-typed. The current descriptors
provide canonical type names and eligibility only; they are not codecs or value
models for all eighteen entity kinds. Opaque bytes, type-name strings, or the
twelve restricted runtime bodies are forbidden substitutes.

Implementation may resume only after the full candidate record/digest preimage,
all-entity typed mutation value codecs, bound precondition payloads,
`Principal`, validation profile, expiry representation, capability-summary
digest contract, and proposal-versus-authority boundary are frozen. This
deferral does not block independent S20-370 policy design and implementation.

S20-345 now freezes those proposal contracts in six normative specs and
ADR-0017. The candidate has thirteen digest-bound fields; operations select
manifest-generated typed codecs for all eighteen entity kinds; preconditions
use only absence/exact-entity/exact-container payloads; capability summaries
are unauthoritative projections; validation profiles require all fourteen
phases; and expiry uses explicit Unix milliseconds without ambient clock
access. No builder, decoder, apply path, root construction, validation, session
authority, capability consumption, transaction, receipt, or CAS exists.

S20-345 also adds identifier-domain types and fixed vectors for
capability-summary and validation-profile identities. Nabu and Vulcan found no
open P0, P1, or P2 issue in the freeze. S20-350 remains a separate
implementation package and is not unblocked by code presence because no
candidate/value codec exists yet.
