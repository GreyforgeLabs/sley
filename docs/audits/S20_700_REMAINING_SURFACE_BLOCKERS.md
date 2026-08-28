# S20-700 Remaining-Surface Blockers

Status: **merge boundary absent; full S20-700 remains incomplete**

Section 18.5 names eleven required persistent-fuzz surfaces. Eleven landed
libFuzzer binaries exercise ten of those required surfaces because the single
`ssmc_graph_cfg_checker` target covers both graph and CFG judgments. Two
additional binaries cover the adjacent S20-360 candidate-result importer and
the S20-390 transaction/receipt importers. The only remaining required gap is
the merge engine.

## Mutation candidates

S20-350 exposes the production proposal-only record/envelope boundary with
complete native structural codecs, bound preconditions, digest verification,
and deterministic creation IDs. The `mutation_candidate` target drives the
real build/import and decode/encode APIs and passed its fixture-seeded smoke. It
exposes no validation authority, mutation application, or state transition.

## Candidate results

S20-360 adds a fixture-seeded persistent target over the production result
importer. Sixteen accepted seeds cover `VALID` plus every terminal decision;
four structural corruptions and five synthetic seeds exercise strict envelope
rejection. Successful imports must repeat byte-identically, rederive the exact
result ID, and preserve the fourteen-phase monotonic shape. This extra target
does not replace any Section 18.5 surface and grants no candidate or commit
authority.

## Transactions and receipts

S20-390 adds a fixture-seeded persistent target over both production importers.
Trusted-genesis and ordinary receipts, eight envelope corruptions, one
digest-valid wrong-manifest-length receipt, and synthetic boundary seeds drive
strict import. Successful imports must repeat, rederive exact transaction and
receipt identities, preserve trailers, and retain nested bindings. Repository
closure separately rejects the wrong authenticated object length. This is an
adjacent hardening surface rather than one of Section 18.5's eleven named
minimums.

## Merge engine

S20-520 has no implementation. Its S20-500 native ref/branch prerequisite is
implemented locally, while its S20-510 semantic comparison prerequisite is
absent. S20-510 remains blocked because full S20-250 still lacks six canonical
entity bodies and complete-root impact semantics. S20-530 is the next
dependency-complete repository package. There is no merge
request, conflict object, or merge judgment to invoke. A synthetic merge fuzzer
would define semantics outside the frozen dependency graph.

Protocol remains an adjacent future fuzz gap, but it is not one of the eleven
minimum persistent surfaces listed in Section 18.5 and S20-410 is not landed.

No placeholder merge target is created for the absent boundary. S20-700 remains
incomplete, the complete finding register and independent review remain
deferred, and `make v2` remains a release-boundary gate. The scoped S20-600 and
S20-610 mechanics, S20-650 unavailable disposition, and bounded S20-710 audit
have since landed. Restricted S20-360 candidate validation, restricted S20-390
atomic commit, and S20-500 native refs are complete. S20-510 remains blocked
by incomplete full S20-250 semantics. S20-530 is the next dependency-complete
package; the current cross-lane result is
`docs/audits/S20_LOCAL_COMPLETION_FRONTIER.md`.

Focused validation:

```text
python3 scripts/check_s20_700_frontier.py
make transaction-receipt-persistent-fuzz-smoke
make check-changed
```
