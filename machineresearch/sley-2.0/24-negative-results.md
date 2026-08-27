# Negative Results

The Sley 1.2.0 source snapshot preserves prior failed bootstrap and training
experiments. No Sley 2 implementation experiment has run yet. New failures,
timeouts, rejected designs, fuzz findings, and benchmark losses must be appended
with inputs and evidence; they may not be deleted from denominators.

## 2026-08-27 — Merlin S20-110 handoff timeout

The bounded Merlin gateway timed out, recovery fell back to an embedded agent,
and the handoff expired without a final answer or commit. It left a coherent
uncommitted `sley-id` crate and Cargo changes in the shared worktree. Codex
inspected the complete diff, ran the required tests/format/clippy/tree checks,
updated repository gates, and sent the recovered implementation to Vulcan,
which returned PASS. No partial result was silently treated as specialist
approval; Merlin's timeout remains recorded separately from code acceptance.
