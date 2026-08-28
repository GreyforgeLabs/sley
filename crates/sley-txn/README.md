# sley-txn

`sley-txn` owns Sley 2 transaction-core and complete-receipt bytes, fresh
commit-time validation orchestration, immutable-object installation, and the
fixed durable accepted-head compare-and-swap primitive.

It does not own named refs, branches, merge, protocol, source, Git, providers,
or policy transitions. The currently implemented profile is restricted to
executable programs containing no semantic operation entities and to an empty
selected-test set. Candidate mutation operations remain supported within that
explicit boundary, as specified by `docs/spec/TRANSACTION_MODEL_V1.md`.
