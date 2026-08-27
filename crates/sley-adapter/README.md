# sley-adapter

Restricted, deterministic S20-280 reference fixtures for adapter conformance
and replay evidence. The crate implements captured stdout/stderr, canonical
virtual files, configured clock ticks, a counter-derived random stream, an
explicit environment map, and exact typed replay entries.

All fixture state is caller-owned memory. This crate never reads or writes the
host filesystem, environment, clock, RNG, network, process table, shell,
secrets, deployment surface, or a provider. Its state and transcript IDs are
derived evidence only; they grant no policy, capability, canonical-state, or
live-resource authority.

S20-380 adds an authorized wrapper that derives a conservative charge from the
complete adapter-limit envelope, verifies and charges a `sley-policy`
capability, and only then delegates to the clone-before-commit fixture
function. The original fixture API remains conformance-only and
unauthoritative. VM adapter opcodes, live host confinement, and persistent
execution/test reports remain fail closed in later work packages.
