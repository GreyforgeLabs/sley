# S20-700 Semantic-Checker Persistent Slice

Status: scoped persistent landed-surface slice; **full S20-700 remains incomplete**

This slice adds two libFuzzer targets at existing public typed boundaries:

- `type_checker` constructs bounded `TypeDefinition` and `TypeExpr` values and
  repeats the S20-210 environment, shape, trait, and instantiation judgments;
- `ssmc_graph_cfg_checker` starts from four accepted function-graph templates,
  applies up to eight mutations from 33 graph and CFG mutation classes, and
  repeats the public S20-220 judgment.

Both targets cap input at 4,096 bytes. The type generator also has a global
512-node construction budget. The graph target asserts every unmutated template
remains accepted. Both targets assert repeated judgments are identical.

These byte-to-structure mappings are fuzz-only constructors. They are not a
canonical SSMC decoder, do not expose the crate-private partial mutation codec,
and do not define serialized graph, type, CFG, or mutation authority. The graph
target covers the current public S20-220 graph-inventory and CFG boundary; it
does not claim a future complete SSMC object decoder.

The deterministic runtime corpora contain 385 type-checker seeds and 396
graph/CFG seeds. Corpus, binaries, artifacts, and command evidence remain under
ignored `evidence/runtime/s20-700-semantic-checkers-libfuzzer/` paths.

## Closed harness finding

`S20-700-HARNESS-001` is the minimized one-byte input `c2`. The first smoke run
showed that the original fuzz-only type generator could expand a cyclic byte
stream exponentially before its depth limit and hit libFuzzer's memory limit.
This was not a production checker defect. The generator now enforces the global
512-node budget, the minimized input is retained in
`fuzz/regressions/S20_700_HARNESS_001.json`, corpus generation consumes that
fixture, and the repeated smoke run passes.

Independent Vulcan review remains deferred because the local Forge OAuth
session returns 401. Query requests, mutation candidates, merge, VM canonical
inputs, adapter responses, and the full finding register remain required.

Focused validation:

```text
cargo +nightly-2026-02-27 clippy --manifest-path fuzz/Cargo.toml --bin type_checker --bin ssmc_graph_cfg_checker -- -D warnings
python3 scripts/check_semantic_checkers_persistent_fuzz_slice.py
make semantic-checkers-persistent-fuzz-smoke
python3 scripts/run_semantic_checkers_persistent_fuzz.py --manual --target type-checker
python3 scripts/run_semantic_checkers_persistent_fuzz.py --manual --target graph-cfg
```
