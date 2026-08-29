# S20-610 raw-file baseline runner

This directory contains an offline-only, injected-adapter evidence runner for
the raw-file benchmark arm. It validates a complete frozen run manifest,
enforces shared fairness controls, creates the manifest exactly once, and
appends canonical digest-chained **claims** for every injected success,
rejection, timeout, or harness failure.

The module has no subprocess, shell, provider, model, network, ambient clock,
live oracle, raw-workspace copier, or Sley 1.x adapter. Those interfaces are
Protocols only. Actual trials require an operator-approved run manifest with
real fixture, model, tool, oracle, hardware, cache, seed, budget, and
environment facts. The separate `<SLEY1_CHECKOUT>` deployment tree is not
read, written, imported, or executed.

The chain proves only continuity and tamper detection for the claim bytes it
contains. It does not verify that named artifacts exist, match their digests,
or came from an approved oracle/accounting adapter. Every record therefore
carries `UNVERIFIED_INJECTED_DIGEST_CLAIMS` plus explicit unverified oracle and
accounting status. No API promotes a claim to benchmark evidence; that requires
a later approved artifact store and provenance verifier.

`accepted_change_tokens` remains `null` in trial metrics because S20-630 owns
derivation from preserved token counts and accepted changes. This package
records no benchmark result and makes no succession or superiority claim.
