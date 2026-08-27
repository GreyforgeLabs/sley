# VM and Adapter Model

Status: S20-260 restricted lowering implemented; no VM execution or adapter.

Deterministic report digests exclude measured wall time. Typed confined
adapters, exact cache binding, frozen floating behavior, cancellation, and no
arbitrary shell are required by S20-260 through S20-290.

The `O0-restricted-v1` profile lowers successful S20-210/S20-220 Function CFGs
for all five terminators and `bool_not`, `bool_and`, and `bool_or`. It assigns
dense registers deterministically, emits exact derived bytes, and derives a
dedicated cache key bound to the epoch descriptors, state root, entry Function,
VM/lowerer versions, and explicit restricted-profile fields. The other 52
opcode signatures, generics, adapter ABIs, execution flags, decoding, and
execution remain unavailable and fail closed where they reach this boundary.
