# Evidence Gaps

- M1 is complete for its implemented canonical-state scope. Four bounded
  S20-700 slices now cover schema bootstrap, adapter binding, object-store
  symlink confinement, and the currently supported private mutation-value
  boundary. SCB1 decoder, direct schema-bootstrap, and S20-170 repository-pack
  importer persistent libFuzzer slices now exist. A bounded public typed
  S20-210 type-checker target and typed graph/CFG persistent target now exercise
  the current S20-220 boundary. A restricted typed S20-310 target now exercises
  all four implemented modeled-snapshot query kinds. A restricted typed S20-270
  target now exercises six identity fixtures and all three supported Boolean
  opcodes under bounded canonical and mismatched inputs. A restricted typed
  S20-280 target now exercises all eight in-memory reference kinds and six
  GenericReplay response schemas.
  The production candidate target now exercises raw record and stored-envelope
  round trips. An additional production candidate-result target exercises all
  sixteen decisions, strict import, and monotonic phase shape. A second adjacent
  target covers strict transaction and receipt import plus identity/binding
  invariants. The merge surface remains blocked; protocol is an adjacent future
  surface outside Section 18.5's minimum eleven.
- The typed graph/CFG persistent target is deliberately a fuzz-only structure
  generator. SSMC still has no public canonical graph decoder, and the target
  neither exposes the crate-private partial mutation codec nor claims a
  serialized graph contract.
- The restricted-query target is also a fuzz-only typed constructor. It does
  not claim a canonical query decoder, the nineteen root-backed query classes,
  continuation, or master context-capsule authority.
- The restricted-VM target is a fuzz-only typed input constructor over nine
  fixed valid graphs. Sley 2 has no raw-bytecode decoder or execution entry
  point, and the target does not cover the other 52 opcode signatures,
  generics, adapters, live cancellation, execution flags, decoding, or
  persistent reports.
- The adapter-response target is a fuzz-only typed fixture constructor over
  request-owned memory. It does not cover the authorized S20-380 wrapper, VM
  adapter opcodes, live host confinement, handle cleanup, or persistent
  execution and replay reports.
- S20-350 is complete as a proposal-only construction boundary after ADR-0019
  aligned generic `Option<T>` with SCB1. Combined independent fixtures cover
  all eighteen bodies, seventy-five fields, recursive aggregates,
  preconditions, candidates, and envelope/digest rejection. The production
  candidate target and focused local review pass. Construction grants no
  semantic validity, runtime mutation authority, or commit permission.
- Restricted S20-360 candidate validation is complete for the explicit
  executable-program-operation-free success subset. The validator owns all fourteen ordered
  phases, recomputes supported semantic fingerprints, invokes native
  type/CFG/effect/contract owners, verifies policy/capability inputs without
  ledger mutation, reconstructs the root in memory, and produces canonical
  results. Sixteen accepted result vectors and four corruptions pass the
  independent Python oracle. Complete operation analysis, mandatory GA
  fingerprint coverage, and runtime authority remain absent.
- Restricted S20-390 atomic commit is complete for that same semantic subset
  with no selected tests. Fresh revalidation, non-cyclic transactions and
  receipts, durable object/receipt-before-head ordering, stale-safe fixed-head
  CAS, current-closure/direct-parent recovery, independent conformance, and a
  five-boundary fault matrix pass. Named refs/branches, recursive full recovery,
  clone-equivalent transaction exchange, and runtime authority remain absent.
- Full-GA S20-240 through S20-270 semantics, adapters, persistent reports, and
  all remaining M2–M6 runtime, query, mutation, policy, repository,
  adversarial, succession, packaging, reproducibility, and independent-review
  evidence.
- Production schema epoch, full candidate-commit semantics, final artifact, and
  succession decision.

These post-M0 gaps prevent any GA or superiority claim.

The current cross-lane audit is
`docs/audits/S20_LOCAL_COMPLETION_FRONTIER.md`. It records S20-500 native refs
and branches as the next authority-safe package. This is an active work
frontier, not product completion.
