# S20-700 VM Canonical-Input Persistent Slice

Status: scoped persistent landed-surface slice; **full S20-700 remains incomplete**

This slice adds one libFuzzer target at the public typed restricted S20-270 VM
boundary. It selects nine fixed valid functions:

- six identity functions over `Unit`, `Bool`, `Bytes`, `Text`, `Option<Bool>`,
  and `Result<Bool, Unit>`;
- three Boolean functions using `BoolNot`, `BoolAnd`, and `BoolOr`.

One input lane builds values that match each fixture's declared parameter
types. The other builds bounded raw typed or deliberately mismatched
`ConstValue` inputs. Both lanes vary normal, zero, tight, maximum, and raw
execution limits. Every request is submitted twice to both
`validated_execution_input_hashes` and `execute_function`; the target requires
identical judgments. When both succeed, it also verifies schema epoch, state
root, function, and input-hash count bindings and rederives the exact
observation ID. Canonical fixture inputs under the normal limit profile must be
accepted, preventing a deterministic reject-all regression from passing.

Input is capped at 4,096 bytes. Raw requests contain at most four values,
collections at most four items, and byte or text payloads at most 32 bytes. The
deterministic synthetic corpus contains 625 seeds. Corpus, binaries, artifacts,
and command evidence remain under ignored
`evidence/runtime/s20-700-vm-input-libfuzzer/` paths.

The byte mapping is a fuzz-only typed constructor, not a VM bytecode format.
The target calls the existing public execution API, which re-lowers a validated
graph. Sley 2 has no raw-bytecode decoder or execution entry point, and this
slice claims neither. It covers the restricted three-opcode execution profile
and identity pass-through inputs only. The other 52 opcode signatures,
generics, adapters, live cancellation, execution flags, decoding, persistent
reports, and full S20-270 remain unavailable.

Independent Vulcan review remains deferred because the local Forge OAuth
session returns 401. Mutation candidates, merge, and the full S20-700 finding
register remain required.

Focused validation:

```text
cargo +nightly-2026-02-27 clippy --manifest-path fuzz/Cargo.toml --bin vm_canonical_inputs --target-dir evidence/runtime/s20-700-vm-clippy-target -- -D warnings
cargo test -p sley-vm --locked
python3 scripts/check_vm_execution_profile.py
python3 scripts/check_vm_persistent_fuzz_slice.py
make vm-persistent-fuzz-smoke
python3 scripts/run_vm_persistent_fuzz.py --manual
```
