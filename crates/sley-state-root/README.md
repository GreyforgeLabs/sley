# sley-state-root

Deterministic S20-160 `StateRoot` construction and strict import for Sley 2.

This crate exposes only registry-authorized construction/import. The current
public authority is a frozen nonzero conformance epoch with an exact tag-160
descriptor and preserved decoder; it is not a claim that the complete Sley 2
production epoch is frozen. The all-zero fixture exercises bytes and hashing
only and is rejected by the authorized import path.

The descriptor hashes are frozen raw BLAKE3 evidence values, not `ObjectId`
values and not uses of the `sley2.object.v1` domain. Construction sorts semantic
collections, while import rejects noncanonical bytes without normalization.

No public input represents repository refs, transactions, paths, ancestry,
time, Git, caches, source, or model output. This crate creates no ref, receipt,
commit, storage, migration, pack, or publication authority.
