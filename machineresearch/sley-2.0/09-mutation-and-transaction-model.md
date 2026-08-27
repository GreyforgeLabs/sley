# Mutation and Transaction Model

Status: S20-340 immutable mutation-schema generation implemented; S20-350
through S20-390 remain normative drafts with no implementation.

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
