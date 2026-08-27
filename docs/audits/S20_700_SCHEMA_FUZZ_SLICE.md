# S20-700 Bounded Schema Fuzz Slice

Status: bounded and persistent landed-surface slices; **full S20-700 remains incomplete**

This slice hardens the completed S20-140 schema boundary without beginning any
blocked mutation, transaction, protocol, merge, or release package.

It adds:

- 512 fixed-seed inputs, each bounded to 2,048 bytes, against the `SLEYEP01`
  bootstrap importer;
- near-canonical truncation, trailing-byte, bit-flip, byte-replacement, and
  arbitrary-byte cases;
- canonical reconstruction checks for every accepted input;
- an exact-selection adversarial test proving unknown epoch and contract IDs do
  not invoke a decoder, and a selected decoder failure does not fall back to a
  different epoch;
- a persistent libFuzzer target for the direct `SLEYEP01` bootstrap importer,
  seeded deterministically from the committed schema-epoch conformance vector;
- exact canonical re-encoding and `SchemaEpochId` preservation assertions for
  every successful persistent decode;
- routine `make fuzz-smoke` coverage and a machine-readable scope checker.

No crash, hang, permissive decode, or fallback finding was discovered. The
persistent target covers only direct schema bootstrap import. It does not cover
registry construction or registry dispatch, and it does not complete the master
goal's required persistent targets for SSMC graph/type/CFG, queries, mutation
candidates, pack import, merge, VM canonical inputs, or adapter responses. Any
future discovered failure still requires a minimized fixture, stable finding
ID, regression test, and root-cause disposition.

Vulcan's earlier independent bounded-slice review found no open P0, P1, or P2
issue. The decoder call counters make epoch/contract fallback assertions
effective. That verdict predates the persistent target. A bounded review
handoff for the new target was attempted but could not start because the local
Forge OAuth session returned 401, so an additional Vulcan review remains
deferred. Neither result is a full S20-700 or release disposition.

Focused validation:

```text
cargo test -p sley-schema bounded_schema_bootstrap_import_fuzz_smoke --locked
cargo test -p sley-schema registry_decode_never_falls_back_across_epoch_or_contract --locked
make fuzz-smoke
python3 scripts/check_schema_fuzz_slice.py
make schema-persistent-fuzz-smoke
python3 scripts/run_schema_persistent_fuzz.py --manual
```
