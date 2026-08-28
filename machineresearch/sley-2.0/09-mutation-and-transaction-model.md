# Mutation and Transaction Model

Status: S20-340 immutable mutation-schema generation and S20-345 candidate
contract/identity freeze complete; S20-350 proposal construction is complete;
S20-360 through S20-390 remain required and have no implementation.

The refined DAG makes the complete validator depend on protected policy and
capability work. S20-340 through S20-390 must prove exact preimages, monotonic
phases, invalid-state immutability, durability, and CAS receipts.

S20-340 now generates descriptor-only Rust data from the exact frozen SSMC1
epoch-1 manifest. The committed artifact covers all eighteen entity kinds,
seventy-five body fields, all sixteen primitive mutation classes, and 179
concrete class/kind/field affordances. Its source BLAKE3-256 is
`1983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae`.
The generator applies only the explicit syntactic eligibility rules frozen in
`docs/spec/MUTATION_SCHEMA_V1.md`, and the routine gate requires exact
regeneration.

The native S20-350 layer now has manifest-selected operation-value codecs,
bound precondition records, and an exact candidate builder/importer. It remains
proposal data, not mutation authority. There is no mutation applier, repository
write, workspace/root/session authority, policy/capability judgment,
transaction, receipt, or CAS surface. S20-360 through S20-390 remain required
before M3/M4 or accepted-state changes.

S20-350 native construction binds workspace, roots, principal, capability
summary, expiry, all sixteen mutation payload classes, and exact preconditions
into schema-typed bytes. Opaque bytes, type-name strings, or the twelve
restricted runtime bodies remain forbidden substitutes. Construction proves
only canonical proposal structure; caller fields are not authenticated facts.
The retained and supplemental independent corpora jointly cover all eighteen
bodies, seventy-five fields, recursive constant/terminator families,
preconditions, all mutation classes, the candidate record, and envelope/digest
failures. The production persistent target asserts byte-identical record
round trips and exact stored-candidate import/rebuild behavior.

Implementation resumed only after the full candidate record/digest preimage,
all-entity typed mutation value codecs, bound precondition payloads,
`Principal`, validation profile, expiry representation, capability-summary
digest contract, and proposal-versus-authority boundary were frozen. S20-345
froze those surfaces, and ADR-0019 then removed the remaining generic
`Option<T>` contradiction without changing a production epoch or accepted
root. S20-350 is therefore complete as construction, while every semantic
authority and state-transition boundary remains deferred.

S20-345 now freezes those proposal contracts in six normative specs and
ADR-0017. The candidate has thirteen digest-bound fields; operations select
manifest-generated typed codecs for all eighteen entity kinds; preconditions
use only absence/exact-entity/exact-container payloads; capability summaries
are unauthoritative projections; validation profiles require all fourteen
phases; and expiry uses explicit Unix milliseconds without ambient clock
access. The native builder and decoder now exist. No apply path, root
construction, semantic validation, session authority, capability consumption,
transaction, receipt, or CAS exists.

S20-345 also adds identifier-domain types and fixed vectors for
capability-summary and validation-profile identities. Nabu and Vulcan found no
open P0, P1, or P2 issue in the freeze. S20-350's independent conformance,
production candidate fuzz smoke, and focused local security review now pass.
No candidate authority exists; S20-360 must produce the separate monotonic
validation result before S20-390 can ever commit.
