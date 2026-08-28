# S20-700 Remaining-Surface Blockers

Status: **merge boundary absent; full S20-700 remains incomplete**

Section 18.5 names eleven required persistent-fuzz surfaces. Nine landed
libFuzzer binaries exercise ten scoped surfaces because the single
`ssmc_graph_cfg_checker` target covers both graph and CFG judgments. The only
remaining required gap is the merge engine.

## Mutation candidates

S20-350 exposes the production proposal-only record/envelope boundary with
complete native structural codecs, bound preconditions, digest verification,
and deterministic creation IDs. The `mutation_candidate` target drives the
real build/import and decode/encode APIs and passed its fixture-seeded smoke. It
exposes no validation authority, mutation application, or state transition.

## Merge engine

S20-520 has no implementation. Its S20-500 native ref/branch and S20-510
semantic comparison prerequisites are also absent, and S20-500 itself depends
on the unavailable S20-390 transaction boundary. There is no merge request,
conflict object, or merge judgment to invoke. A synthetic merge fuzzer would
define semantics outside the frozen dependency graph.

Protocol remains an adjacent future fuzz gap, but it is not one of the eleven
minimum persistent surfaces listed in Section 18.5 and S20-410 is not landed.

No placeholder merge target is created for the absent boundary. S20-700 remains
incomplete, the complete finding register and independent review remain
deferred, and `make v2` remains a release-boundary gate. The scoped S20-600 and
S20-610 mechanics, S20-650 unavailable disposition, and bounded S20-710 audit
have since landed. S20-360 candidate validation is now the next dependency-complete package;
the current cross-lane result is
`docs/audits/S20_LOCAL_COMPLETION_FRONTIER.md`.

Focused validation:

```text
python3 scripts/check_s20_700_frontier.py
make check-changed
```
