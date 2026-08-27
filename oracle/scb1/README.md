# Independent SCB1 oracle

This Python package is the S20-130 implementation-independent conformance
oracle for SCB1. It consumes only the frozen JSON fixtures and implements the
encoding, envelope hashing, strict decoding, and rejection taxonomy directly.
It does not import, execute, or inspect the Rust codec.

The package also checks the explicitly partial S20-350 mutation-value corpus.
That isolated path covers 126 accepted and 18 rejected vectors for landed,
unambiguous private codec families, including all twenty `TypeExpr` variants,
eleven entity-body records, and exact declared-value fixtures for 65 of the 75
manifest fields. It deliberately excludes generic `Option<T>`, `ConstValue`,
deferred bodies and contract/test unions, the ten dependent fields, aggregate
and candidate records, and runtime surfaces. Its semantic encoding/decoding logic remains Python-only; committed
expected bytes are consumed independently by the Rust fixture tests.

The environment pins Python `blake3` 1.0.9 and `unicodedata2` 16.0.0. Run the
repository-level `make conformance` target to execute both oracle gates. The
partial mutation-value gate can be run directly with:

```bash
uv run --project oracle/scb1 --frozen sley2-scb1-oracle check-mutation-value \
  --accepted conformance/mutation-value/v1/accepted.json \
  --rejected conformance/mutation-value/v1/rejected.json
```
