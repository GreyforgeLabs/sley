# sley-repo

`sley-repo` implements the S20-170 uncompressed, root/object-only repository
pack contract. Import preflights the complete pack before promoting immutable
objects. Refs, transactions, signatures, and compressed profiles are rejected
until later work packages define them.

The crate also implements S20-180 explicit retention snapshots, deterministic
dry-run reports, schema-selected object-reference traversal, strict store
inventory, and exclusive-guarded deletion of verified unreachable objects.
