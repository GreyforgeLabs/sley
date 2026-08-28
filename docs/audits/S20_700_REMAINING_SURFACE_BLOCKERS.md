# S20-700 Remaining-Surface Blockers

Status: **two required production surfaces absent; full S20-700 remains incomplete**

Section 18.5 names eleven required persistent-fuzz surfaces. Eight landed
libFuzzer binaries currently exercise nine scoped surfaces because the single
`ssmc_graph_cfg_checker` target covers both graph and CFG judgments. The two
required surfaces without production boundaries are mutation candidates and
the merge engine.

## Mutation candidates

S20-340 exposes immutable descriptors. The partial S20-350 foundation exposes
closed proposal host values, descriptor-to-value admission, and crate-private
leaf/body codecs. It explicitly provides no aggregate candidate codec,
candidate constructor, precondition evaluator, validation authority, mutation
application, or state transition. ADR-0019 resolves generic `Option<T>` and the
S20-345 `ConstValue` contract is frozen, making S20-350 implementation-ready.
Until the aggregate codecs and candidate constructor land, a persistent target
would still fuzz a parallel constructor rather than production candidate
behavior.

## Merge engine

S20-520 has no implementation. Its S20-500 native ref/branch and S20-510
semantic comparison prerequisites are also absent, and S20-500 itself depends
on the unavailable S20-390 transaction boundary. There is no merge request,
conflict object, or merge judgment to invoke. A synthetic merge fuzzer would
define semantics outside the frozen dependency graph.

Protocol remains an adjacent future fuzz gap, but it is not one of the eleven
minimum persistent surfaces listed in Section 18.5 and S20-410 is not landed.

No placeholder target is created for any absent boundary. S20-700 remains
incomplete, the complete finding register and independent review remain
deferred, and `make v2` remains a release-boundary gate. The scoped S20-600 and
S20-610 mechanics, S20-650 unavailable disposition, and bounded S20-710 audit
have since landed. S20-350 is now the next dependency-complete package; the
current cross-lane result is `docs/audits/S20_LOCAL_COMPLETION_FRONTIER.md`.

Focused validation:

```text
python3 scripts/check_s20_700_frontier.py
make check-changed
```
