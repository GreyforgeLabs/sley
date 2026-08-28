# Sley 2 Local Completion Frontier

Status: **S20-350 proposal construction is complete; S20-360 validation is next; the Sley 2 goal remains incomplete**

This audit records the first unavailable boundary in each unfinished lane and
the one dependency-complete package that may proceed. It does not convert
restricted profiles into GA, substitute documentation for implementation, or
authorize accepted-state mutation, benchmarks, release, or publication.

ADR-0019 corrected the unreleased epoch-1 generic `Option<T>` declaration to
the canonical SCB1 tags (`0=None`, `1=Some<T>`). No production schema epoch,
accepted root, release artifact, or compatibility promise existed, so the
manifest and all derived evidence could be re-anchored together. The
`ConstValue` record and its closed sixteen-variant type/data contract were
already frozen by S20-345. The native implementation, independent Python
corpus, exact Rust consumer, and production candidate libFuzzer target now close
proposal-only candidate construction. They do not supply semantic validation,
authority, or state mutation.

| Lane | Current boundary | Status |
|---|---|---|
| Semantics and queries | Full S20-240/S20-250 | Six entity bodies remain outside the semantic-core ownership and exact impact contract; complete-root extraction is absent. |
| Sessions and protocol | S20-330/S20-400 | Verified workspace/root/epoch and negotiated-session authority are absent. S20-400 also waits for full S20-310, S20-350, and S20-390. |
| Mutation and transactions | S20-360 | S20-350 is complete as a proposal-only construction boundary. The ordered candidate-result validator is absent; S20-390 commit remains dependency-blocked. |
| Repository | S20-500 | The transaction/receipt boundary is absent, so native refs, comparison, merge, recovery integration, and clone equivalence cannot begin honestly. |
| Succession benchmark | Full S20-600/S20-610 and S20-620 | The verified legacy adapter and offline raw claim chain are mechanics only. Approved fixtures, containment, live adapters, artifact/oracle/accounting verification, protocol/CLI, and real trials are absent. |
| Adversarial | Full S20-700 | The candidate production target is attached and passing. The merge production boundary remains absent, so the eleventh required surface cannot yet be fuzzed. |
| Supply chain and release | Full S20-710/S20-720 | Root license text approval, standards SBOM, provenance, release re-anchor, final review, all GA code, and a release artifact are absent. |

## S20-250 remains incomplete

The epoch-1 schema freezes fields for `Workspace`, `Package`, `Namespace`,
`EntryPoint`, `PolicyBinding`, and `DependencyBinding`, but the current
`sley-ssmc` semantic core models only kinds 4 through 15. Before full S20-250
can land, one normative model must own all eighteen bodies and freeze the exact
workspace membership, package dependency/export, namespace parentage,
entry-point exposure, policy-subject, and external-root relationships. A
second host model or locally invented edge kinds remain forbidden.

## Active package and terminal facts

- S20-360 candidate validation is the next authority-safe package. Its inputs
  are the completed S20-350 proposal, existing semantic checks, and the
  protected S20-370/S20-380 policy/capability boundaries.
- The epoch re-anchor has architecture and semantic review. Vulcan's first
  re-anchor pass found stale machine-summary query/capsule vectors; after those
  and later adapter/report identities were corrected, the focused re-review
  passed with no report-grade findings.
- S20-350 candidate construction is proposal-only. Native tests build and
  import candidate bytes, but no candidate has been executed, semantically
  validated, applied, committed, or treated as authority.
- The focused Codex semantic/security review found no report-grade issue.
  Specialist re-review remains recorded as deferred because Forge OAuth returns
  401; it is not represented as an independent Vulcan pass.
- `make v2` and `make release-check` remain fail-closed `NOT_IMPLEMENTED`
  gates and are not success evidence.
- No `sley-txn`, `sley-protocol`, `sley-json-bridge`, or `sley-cli` crate and no
  repository merge production module exists.
- No real benchmark trial, release artifact, publication authority, provider
  spend, push, tag, upload, or deployment exists in this goal.

`python3 scripts/check_local_completion_frontier.py` fails if the recorded
boundary drifts. S20-350 is closed; the next action is the smallest
dependency-complete package, S20-360, without widening construction into
authority or accepted-state mutation.
