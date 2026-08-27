# sley-check

Deterministic semantic judgment for Sley 2.

S20-210 implements the bounded core type system: structural well-formedness,
explicit invariant substitution, definition-cycle rejection, type traits, and
constant/type agreement. S20-220 adds bounded graph inventory, reachability,
dominance, value-use, edge, switch, and trap validation with stable failure
precedence. S20-230 adds exact least-fixed-point effect closure, typed direct
calls and effect operations, canonical static scopes, and a strict boundary
before runtime capability/policy authority. Contracts, remaining opcode
semantic signatures, fingerprints, lowering, execution, protected policy,
repository, and protocol judgment remain later packages.

S20-240 additionally validates the restricted epoch-1 contract/test profile:
pure non-generic function predicates, immutable global bindings, typed contract
assertions, pure value/trap tests, explicit rejection of underspecified schema
forms, and deterministic provisional selection marked policy-incomplete. It
does not claim full-GA invariants, effectful tests, replay, observations,
resource evidence, predicate execution, or final policy selection.
