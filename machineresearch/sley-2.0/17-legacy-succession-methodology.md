# Legacy Succession Methodology

Status: S20-040 design and corpus complete; S20-600–630 runners pending.

Mandatory arms are raw-file editing, frozen Sley 1.2.0, and Sley 2.0 under the
same model, intent, action/context/wall budgets, environment, retry policy, and
oracle. Every attempt remains in the denominator. ACT is observable model
tokens divided by accepted correct changes and never overrides correctness.

The task/oracle intent is frozen before any Sley 2 semantic implementation.
Per-arm fixtures may encode the same intent differently but cannot change the
oracle or task statement. Corpus changes create a new version and preserve v1.
