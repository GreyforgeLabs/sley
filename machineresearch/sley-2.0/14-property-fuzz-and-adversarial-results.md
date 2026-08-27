# Property, Fuzz, and Adversarial Results

Status: bounded partial S20-700 evidence. This is not a persistent fuzz harness,
the complete cross-surface suite, or a final finding register. The 55-threat map
remains `docs/THREAT_REGISTER.md`.

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

The mutation-value slice is selected by:

```bash
cargo test -p sley-mutate bounded_mutation_value_codec_fuzz_smoke --locked
cargo test -p sley-mutate mutation_value_codec_adversarial --locked
```

Vulcan's bounded implementation review and Merlin's independent read-only code
review found no report-grade issue. Generic `Option<T>`, `ConstValue`, aggregate,
candidate, runtime, merge, protocol, VM-input, and adapter-response fuzz targets
remain outside this slice. Persistent fuzzing and minimized finding retention
remain mandatory before S20-700 completion.
