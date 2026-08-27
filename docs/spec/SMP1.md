# Sley Machine Protocol v1 (SMP1)

Status: M0 normative draft; numeric method tags are not frozen.

SMP1 is the primary programming interface. It is bounded, version-negotiated,
request/response, cancellation-aware, machine-code first, and transport-neutral
above framing. Prose is optional debug metadata.

## Reference framing

The reference transport is stdio. A frame is an unsigned 64-bit big-endian
payload length followed by one canonical SCB1 protocol envelope. Negotiated
limits are checked before allocation. An optional checksum is enabled only by
an explicit transport profile and never changes payload semantics.

Each envelope binds protocol version, request/response ID, method tag, flags,
and typed payload. IDs are scoped to one negotiated session. Duplicate,
conflicting, late-after-close, or cross-session IDs fail with stable codes.

## Handshake

Both peers declare protocol versions, schema epochs, size/entity/depth limits,
methods, effects, adapter identities, compression, JSON bridge profile,
cancellation, and streaming. The selected profile is explicit and digested.
No common safe profile fails closed; no silent downgrade exists.

## Method families

- Session: open, renew, close, capabilities, budgets.
- Repository: create/open workspace, refs, roots, branch, compare, merge, pack.
- Query: typed query, continue, expand handle, diagnostics.
- Candidate: create, append typed operation, validate, inspect, discard.
- Transaction: commit, receipt, checkout, protected ref move, recovery.
- Execution: execute, selected/affected tests, cancel, report.

## Bounded context

Every response reports applied limits, returned byte/entity/edge/depth counts,
omissions, truncation, and continuation. Session-local handles bind session,
workspace, root, and epoch and fail after any binding changes.

## JSON bridge

The JSON bridge is generated from SMP1 contracts. It uses a declared binary
encoding, preserves stable codes and unknown/omission states, and contains no
semantic validation. JSON is non-canonical and cannot participate in program
identity.
