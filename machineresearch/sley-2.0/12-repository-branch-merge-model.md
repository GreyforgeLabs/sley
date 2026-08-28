# Repository, Branch, and Merge Model

Status: restricted S20-390 fixed accepted-head transaction boundary is implemented;
no native named-ref, branch, comparison, or merge implementation exists.

The Section 11.3 duplicate parent-transaction phrase is treated as a textual
duplication. Branches bind one exact parent transaction/root. S20-390 owns only
the fixed `accepted` visibility primitive and canonical transaction/receipt
types. S20-500 through S20-540 own named refs, comparison, merge/conflict, full
crash recovery, and clone-equivalent transaction exchange.
