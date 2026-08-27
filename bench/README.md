# Sley 2 Succession Benchmark

This directory defines representation-neutral task intent and scoring. It is
benchmark metadata, not a Sley program representation and never enters program
identity or kernel judgment.

`corpus/v1/tasks.json` freezes one task for each mandatory class in the master
goal. A later corpus change creates `v2`; it never rewrites v1 after trials.
`benchmark-plan.json` freezes arms, controls, metrics, fairness, thresholds, and
failure retention. Exact model versions, tool contracts, hardware, cache state,
budgets, seeds, and per-arm fixture digests are frozen in a run manifest before
the first trial, because those values do not yet exist at S20-040.

The same task intent, strict semantic oracle, action/context/wall budgets, and
retry policy apply to raw files, frozen Sley 1.2.0, and Sley 2.0. Arm-specific
representations may differ only where the arm intrinsically requires them.
Every attempted trial remains in the denominator.
