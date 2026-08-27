# Execution Model v1

Status: M0 normative draft.

The reference VM is the SSMC1 execution oracle. It is register-based and may
execute derived bytecode whose cache key binds root, entry point, epoch, VM
semantic version, optimization profile, and adapter ABI versions.

An execution request binds canonical inputs, exact root and entry point,
capabilities, adapter identities/versions, deterministic seed or replay, fuel,
time, memory, output, and cancellation limits.

Validated programs have no undefined behavior. Values are immutable by
default; mutation uses explicit local cells. Programs have no raw pointers,
pointer arithmetic, shared mutable global memory, ambient state, or arbitrary
shell. Opaque resources live behind typed handles with deterministic close or
invalidation rules.

Deterministic/replayed runs from the same inputs produce byte-identical values,
effect observations, and observation digests. Wall time is measured metadata
and excluded from the deterministic digest. Canonical map iteration, frozen
floating behavior, and explicit locale/timezone/environment effects prevent
host leakage.

Cancellation stops within a negotiated bound, invalidates handles, commits no
program state, and returns a typed report with resource evidence.
