# S20-700 Restricted-Query Request Persistent Slice

Status: scoped persistent landed-surface slice; **full S20-700 remains incomplete**

This slice adds one libFuzzer target at the public typed S20-310 restricted
query boundary. A fixed valid three-entity function snapshot is rebuilt under
rootless and claimed-root contexts. Bounded fuzz-only constructors then select
all four restricted query kinds, resolved or unresolved entity IDs, canonical
or noncanonical kind and seed sets, and zero, tight, maximum, over-maximum, or
raw bounded resource limits.

For every accepted request, the target asserts:

- `QueryId` is derived from the exact request preimage;
- the preimage remains within the frozen request byte ceiling;
- the request fails with `QUERY_SNAPSHOT_MISMATCH` against the alternate
  snapshot;
- a successful response preserves query, snapshot, context, completeness, and
  applied-limit bindings;
- returned counts, depth, response bytes, and charged work stay within the
  accepted limits;
- rebuilding and executing the same typed request produces the same result.

Input is capped at 4,096 bytes. Kind and seed sets are each capped at 16
generated entries. The deterministic synthetic corpus contains 525 seeds.
Corpus, binaries, artifacts, and command evidence remain under ignored
`evidence/runtime/s20-700-query-request-libfuzzer/` paths.

The byte mapping is a fuzz-only typed constructor, not a canonical query
decoder or serialized request contract. This slice covers only the four
restricted modeled-snapshot query kinds. It does not implement the nineteen
root-backed master-goal query classes, truncation, continuation, master context
capsules, useful cache authority, or proven root provenance.

Independent Vulcan review remains deferred because the local Forge OAuth
session returns 401. Mutation candidates, merge, and the full S20-700 finding
register remain required.

Focused validation:

```text
cargo +nightly-2026-02-27 clippy --manifest-path fuzz/Cargo.toml --bin restricted_query_request --target-dir evidence/runtime/s20-700-query-clippy-target -- -D warnings
python3 scripts/check_query_persistent_fuzz_slice.py
make query-persistent-fuzz-smoke
python3 scripts/run_query_persistent_fuzz.py --manual
```
