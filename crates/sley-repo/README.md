# sley-repo

`sley-repo` implements the S20-170 uncompressed, root/object-only repository
pack contract. Import preflights the complete pack before promoting immutable
objects. The S20-170 pack profile still rejects refs, transactions, signatures,
and compression until S20-540 defines clone-equivalent exchange.

The crate also implements S20-180 explicit retention snapshots, deterministic
dry-run reports, schema-selected object-reference traversal, strict store
inventory, and exclusive-guarded deletion of verified unreachable objects.

S20-500 adds native named branches over durable S20-390 transactions. It uses
strict lowercase ASCII names mapped to digest-keyed paths, immutable origin
records, verified mutable refs, one repository-wide lock, idempotent creation,
direct-parent compare-and-swap advancement, deterministic bounded ancestry,
owned-stage recovery, parent-resynced layout and fan-out creation retries, and
shared maintenance coordination with exclusive GC. It exposes no delete,
force, rename, symbolic-ref, tag, named-branch candidate-commit, merge, or
pack-exchange API.
