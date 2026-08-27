# Legacy Succession Methodology

Status: S20-040 design and corpus complete; scoped S20-600 frozen-artifact and
version-smoke mechanics implemented; full S20-600 and S20-610–630 runners
pending.

Mandatory arms are raw-file editing, frozen Sley 1.2.0, and Sley 2.0 under the
same model, intent, action/context/wall budgets, environment, retry policy, and
oracle. Every attempt remains in the denominator. ACT is observable model
tokens divided by accepted correct changes and never overrides correctness.

The task/oracle intent is frozen before any Sley 2 semantic implementation.
Per-arm fixtures may encode the same intent differently but cannot change the
oracle or task statement. Corpus changes create a new version and preserve v1.

The scoped S20-600 adapter verifies the exact frozen archive and embedded
payload, stages only a private write-bit-stripped copy, and retains the exact
environment and outcome of `bin/sley --version`. The initial 10-second timeouts,
30-second timeout, and successful longer smoke remain runtime evidence. The
stage is not a read-only mount. This command is not a corpus
task and establishes no correctness, fairness, ACT, context, or repair metric.
Real legacy-arm trials remain blocked on a frozen run manifest, task fixtures,
network containment, model/provider and oracle adapters, and every-attempt
accounting.
