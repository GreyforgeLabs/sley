# Property, Fuzz, and Adversarial Results

Status: bounded partial S20-700 evidence with eleven scoped persistent libFuzzer
harnesses. This is not the complete cross-surface suite or a final finding
register. The 55-threat map remains `docs/THREAT_REGISTER.md`.

Current landed slices:

- Schema bootstrap: 512 deterministic inputs, 2,048-byte cap, and exact
  no-fallback registry selection.
- Adapter binding: state-root, effect, and adapter confusion fail before ledger
  charge or fixture mutation.
- Object-store confinement: Unix root and fan-out symlink cases fail without
  writes outside the store.
- Private mutation values: all 126 accepted fixtures seed 252 trailing-byte and
  446 distinct proper-prefix cases, for 698 deterministic derived mutations.
  Every decode/re-encode path is panic-contained; appended data returns
  `SCB_TRAILING_BYTES`; repeated truncations retain the same error code; all 18
  committed rejection vectors retain their exact codes.
- SCB1 decoder persistent libFuzzer slice: a local `fuzz/` target exposes
  `LLVMFuzzerTestOneInput`, multiplexes all frozen SCB1 decoder schemas plus
  both standalone fixture contracts through a one-byte selector, and asserts
  successful standalone decodes re-encode byte-identically with preserved
  `ObjectId`.
- Schema bootstrap persistent libFuzzer slice: a separate local `fuzz/` target
  sends bounded arbitrary bytes to the direct `SLEYEP01` importer and asserts
  that successful imports re-encode byte-identically with a preserved
  `SchemaEpochId`. Its corpus is derived deterministically from the committed
  schema-epoch bootstrap fixture.
- Repository-pack importer persistent libFuzzer slice: a clean temporary store
  receives bounded direct or outer-trailer-rehashed inputs derived from the
  committed S20-170 pack fixture. Failed preflight must promote no object;
  successful import must preserve the exact pack ID and repeat idempotently.
- Type-checker persistent libFuzzer slice: fuzz-only typed constructors feed the
  public typed S20-210 type checker under a global 512-node construction budget.
  Environment, type-shape, trait, and instantiation judgments must repeat
  identically.
- Graph/CFG persistent libFuzzer slice: four accepted function-graph templates
  receive up to eight mutations from 33 classes before the public typed S20-220
  graph/CFG validator runs twice with an identical result.
- Restricted-query request persistent libFuzzer slice: bounded typed
  constructors cover all four S20-310 query kinds, canonical and noncanonical
  set shapes, resolved and unresolved IDs, and limit boundaries. Accepted
  requests preserve identity and reject an alternate snapshot; successful
  responses respect every accepted bound, and judgments repeat deterministically.
- VM canonical-input persistent libFuzzer slice: nine fixed valid functions
  cover six identity types and the restricted `BoolNot`, `BoolAnd`, and `BoolOr`
  opcodes. Bounded canonical or deliberately mismatched typed inputs and limit
  profiles must produce deterministic input-hash and execution judgments.
  Successful outcomes retain epoch, root, function, and observation bindings.
- Adapter-response persistent libFuzzer slice: all eight restricted S20-280
  reference kinds pass through the public typed fixture API. GenericReplay
  varies success and declared-failure values across six structural schemas.
  Equal inputs must repeat, rejection must be atomic, successful receipts must
  bind their state and response type, and transcripts must bind `StateRoot`.
- Mutation-candidate persistent libFuzzer target: fixture-seeded arbitrary
  bytes drive the production proposal-only raw record and stored-envelope APIs.
  Successful record decodes must re-encode byte-identically; successful imports
  must rebuild to the identical record, preimage, candidate ID, and stored
  bytes. The target grants no validation authority or mutation path.
- Candidate-result persistent libFuzzer target: all sixteen canonical terminal
  decisions plus four corruption mutations seed the production result importer.
  Successful imports must repeat identically, rederive their exact digest,
  retain envelope length/trailer integrity, and preserve the fourteen-phase
  monotonic result shape. This adjacent result surface grants no candidate,
  commit, ledger, repository, or runtime authority.
- Transaction/receipt persistent libFuzzer target: canonical trusted-genesis
  and ordinary vectors, nine rejected cases, and synthetic boundaries seed both
  production importers. Successful imports repeat and rederive exact identities
  and nested bindings. A repository adversarial test and independent oracle
  separately reject a digest-valid receipt whose authenticated object length
  differs from durable inventory. This adjacent target grants no runtime or
  named-ref authority.

Closed development finding `S20-700-HARNESS-001` retains minimized input `c2`.
The initial fuzz-only type generator could expand that cyclic one-byte stream
exponentially and reach libFuzzer's memory limit. A global 512-node construction
budget fixes the harness-only issue; the committed regression fixture is part
of corpus generation, and the repeated smoke passes. No production checker
defect was found by that event.

The mutation-value slice is selected by:

```bash
cargo test -p sley-mutate bounded_mutation_value_codec_fuzz_smoke --locked
cargo test -p sley-mutate mutation_value_codec_adversarial --locked
```

Vulcan's bounded implementation review and Merlin's independent read-only code
review found no report-grade issue in the earlier landed slices. Generic
`Option<T>`, `ConstValue`, aggregate, and proposal-only candidate codecs now
have complete independent S20-350 corpus coverage and a production persistent
target. The merge production boundary remains absent; protocol is an adjacent
future surface but is not one of Section 18.5's eleven minimum surfaces.
The restricted VM target does not define or execute raw bytecode and does not
complete S20-270. The adapter target is a conformance-only in-memory fixture,
not VM integration, live host access, or the authorized S20-380 path. The eleven
persistent targets do not complete S20-700;
persistent harnesses for the remaining required surfaces remain absent.
Persistent fuzzing and minimized finding retention remain mandatory before
S20-700 completion. Independent review of the new targets is deferred because
the local Forge OAuth session returns 401.

The SCB1 decoder persistent smoke is selected by:

```bash
make scb1-persistent-fuzz-smoke
python3 scripts/run_scb1_persistent_fuzz.py --manual
```

The schema bootstrap persistent smoke is selected by:

```bash
make schema-persistent-fuzz-smoke
python3 scripts/run_schema_persistent_fuzz.py --manual
```

The repository-pack importer persistent smoke is selected by:

```bash
make pack-persistent-fuzz-smoke
python3 scripts/run_pack_persistent_fuzz.py --manual
```

The semantic-checker persistent smoke is selected by:

```bash
make semantic-checkers-persistent-fuzz-smoke
python3 scripts/run_semantic_checkers_persistent_fuzz.py --manual --target type-checker
python3 scripts/run_semantic_checkers_persistent_fuzz.py --manual --target graph-cfg
```

The restricted-query request persistent smoke is selected by:

```bash
make query-persistent-fuzz-smoke
python3 scripts/run_query_persistent_fuzz.py --manual
```

The VM canonical-input persistent smoke is selected by:

```bash
make vm-persistent-fuzz-smoke
python3 scripts/run_vm_persistent_fuzz.py --manual
```

The adapter-response persistent smoke is selected by:

```bash
make adapter-responses-persistent-fuzz-smoke
python3 scripts/run_adapter_responses_persistent_fuzz.py --manual
```

The candidate persistent smoke is selected by:

```bash
make mutation-candidate-persistent-fuzz-smoke
python3 scripts/run_mutation_candidate_persistent_fuzz.py --manual
```

The candidate-result persistent smoke is selected by:

```bash
make candidate-result-persistent-fuzz-smoke
python3 scripts/run_candidate_result_persistent_fuzz.py --manual
```

The bounded mutation-value post-commit environment, command durations, results,
skipped gates, and scope limits are recorded in
`evidence/validation/s20-700-mutation-value-bounded-v1.json`. Persistent smoke
evidence is written locally under the ignored `evidence/runtime/` paths named in
`machine-summary.json`; it is runtime evidence, not canonical repository state.
