# S20-700 Bounded Schema Fuzz Slice

Status: bounded landed-surface slice; **full S20-700 remains incomplete**

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
- routine `make fuzz-smoke` coverage and a machine-readable scope checker.

No crash, hang, permissive decode, or fallback finding was discovered. This is
a deterministic bounded smoke target, not a persistent fuzz harness. It does
not complete the master goal's required persistent targets for SCB1, schema,
SSMC graph/type/CFG, queries, mutation candidates, pack import, merge, VM
canonical inputs, or adapter responses. Any future discovered failure still
requires a minimized fixture, stable finding ID, regression test, and root-cause
disposition.

Vulcan's independent bounded-slice review found no open P0, P1, or P2 issue.
The decoder call counters make epoch/contract fallback assertions effective;
this verdict is not a full S20-700 or release disposition.

Focused validation:

```text
cargo test -p sley-schema bounded_schema_bootstrap_import_fuzz_smoke --locked
cargo test -p sley-schema registry_decode_never_falls_back_across_epoch_or_contract --locked
make fuzz-smoke
python3 scripts/check_schema_fuzz_slice.py
```
