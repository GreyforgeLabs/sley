# sley-ssmc

Structural SSMC1 data model for the frozen S20-200 through S20-230 surface.

The crate represents all 20 epoch-1 type tags, type definitions, member
identities, function-reference types and values, and persistable constant
forms. It also represents the closed effect kinds, effect definitions, static
capability requirements, and adapter imports judged by `sley-check`. It
represents the frozen contract/test/global/constant bodies used by the
restricted epoch-1 S20-240 profile. It performs no schema selection, SCB
decoding, graph/effect/contract validation, runtime policy or capability
judgment, lowering, execution, repository mutation, or source translation.
