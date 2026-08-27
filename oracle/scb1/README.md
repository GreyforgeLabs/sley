# Independent SCB1 oracle

This Python package is the S20-130 implementation-independent conformance
oracle for SCB1. It consumes only the frozen JSON fixtures and implements the
encoding, envelope hashing, strict decoding, and rejection taxonomy directly.
It does not import, execute, or inspect the Rust codec.

The environment pins Python `blake3` 1.0.9 and `unicodedata2` 16.0.0. Run the
repository-level `make conformance` target to execute the locked oracle gate.
