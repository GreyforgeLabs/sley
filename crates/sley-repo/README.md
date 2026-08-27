# sley-repo

`sley-repo` implements the S20-170 uncompressed, root/object-only repository
pack contract. Import preflights the complete pack before promoting immutable
objects. Refs, transactions, signatures, and compressed profiles are rejected
until later work packages define them.
