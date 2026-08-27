# S20-700 Repository-Pack Import Persistent Slice

Status: scoped persistent landed-surface slice; **full S20-700 remains incomplete**

This slice hardens the completed S20-170 root/object-only repository-pack
importer. It does not begin refs, transactions, compression, signatures,
clone-equivalent exchange, merge, or release packaging.

The libFuzzer target has two deterministic input lanes:

- direct bytes exercise the exact outer envelope, digest, profile, schema,
  state-root, object-closure, verifier, and clean-store import path;
- rehashed bytes replace only the final `RepositoryPackId` trailer so mutations
  can reach inner payload checks instead of stopping at the outer digest.

Both lanes are bounded to 65,536 payload bytes. A failed import must leave the
clean store without an `objects` tree. A successful import must bind the exact
pack ID, find no preexisting objects, and import a second time with identical
roots and present-only object accounting. The fixture verifier is intentionally
limited to the two S20-170 conformance object contracts. It is not a production
object-schema registry or authority.

The deterministic corpus comes from
`conformance/repository-pack/v1/accepted.json` and includes direct and rehashed
canonical, truncation, trailing-byte, and single-bit mutation seeds. Runtime
corpus, binaries, artifacts, and evidence remain under ignored
`evidence/runtime/` paths.

This slice does not cover the deferred full S20-540 pack, merge, protocol,
mutation-candidate, VM-input, or adapter-response surfaces. A bounded Vulcan
handoff could not start because the local Forge OAuth session returned 401, so
independent review of this persistent addition remains deferred.

Focused validation:

```text
cargo test -p sley-repo bounded_pack_import_fuzz_smoke_rejects_rehashed_mutations --locked
python3 scripts/check_pack_persistent_fuzz_slice.py
make pack-persistent-fuzz-smoke
python3 scripts/run_pack_persistent_fuzz.py --manual
```
