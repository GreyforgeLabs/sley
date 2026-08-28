# Repository, Branch, and Merge Model

Status: restricted S20-390 fixed accepted-head transaction boundary is
implemented; the S20-500 native named-ref and branch contract is frozen after
Nabu, Ariadne, and Vulcan review; no S20-500 implementation, comparison, or
merge exists.

The Section 11.3 duplicate parent-transaction phrase is treated as a textual
duplication. Branches bind one exact parent transaction/root. S20-390 owns only
the fixed `accepted` visibility primitive and canonical transaction/receipt
types. S20-500 through S20-540 own named refs, comparison, merge/conflict, full
crash recovery, and clone-equivalent transaction exchange.

The S20-500 draft in `docs/spec/NATIVE_REFS_BRANCHES_V1.md` keeps branch names
out of canonical program identity and host paths. It defines an immutable
origin record, a mutable verified-head record, one refs lock, idempotent
creation, direct-parent fast-forward CAS, and bounded receipt-owned ancestry.
Delete, force movement, symbolic refs, tags, named-branch candidate commit,
comparison, merge, full recovery, and clone-equivalent exchange remain fail
closed.
