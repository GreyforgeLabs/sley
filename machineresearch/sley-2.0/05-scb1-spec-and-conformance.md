# SCB1 Specification and Conformance

Status: S20-100 normative specification, S20-120 Rust codec, and S20-130
independent oracle complete.

The specification freezes the standalone envelope, exact digest preimage,
schema-directed primitive and structural encodings, Unicode 16.0.0 NFC label
boundary, runtime Text preservation, floating canonicalization, deterministic
extensions, epoch maxima, error taxonomy, and migration rules.

Fixture evidence:

- 23 accepted vectors;
- 26 rejected vectors covering 22 stable code classes;
- accepted fixture SHA-256
  `c6b7097b4f03d82c0181b473c3f3d90e028fe53c0ec8ff640c715954b5151e93`;
- rejected fixture SHA-256
  `aaf7f3b2db7c26d79ad212c01858857e145e3ace3547390a53617811ad77f278`;
- one complete stored envelope whose BLAKE3/ObjectId was generated with Rust
  `blake3` 1.8.2 and whose preimage, digest, and stored bytes are frozen;
- Ariadne S20-100 review: PASS after the envelope/digest and all envelope-level
  rejection fixtures were added;
- Python oracle: locked `blake3` 1.0.9 and `unicodedata2` 16.0.0 environment,
  seven unit tests, independent source-dependency check, encode/decode agreement
  on all 23 accepted vectors, and exact error-code agreement on all 26 rejected
  vectors.
- Vulcan S20-130 review: PASS with no P0/P1 findings. Its one P2 portability
  advisory was resolved by replacing the depth-65 generator marker with the
  complete 129-byte rejected input in the frozen corpus.
- Rust codec: unsafe-free `sley-scb1` using `blake3` 1.8.2, `sley-id`
  `ObjectId`, and `unicode-normalization` 0.1.24 with compile-time and runtime
  proof that its tables are Unicode 16.0.0. Three integration tests cover all
  accepted/rejected fixtures plus overflow, canonical ordering, duplicate, and
  epoch invariants.
- Vulcan S20-120 closeout: PASS after two P1 findings were corrected. The
  oracle now binds declared fixture types to envelope contract tags, and
  `check-changed` now executes the conformance target it reports.

`scripts/check_scb1_spec.py` remains the fixture-construction/checksum guard.
The separately locked `oracle/scb1` package constructs and decodes accepted
bytes, hashes and verifies the standalone envelope, parses rejected inputs, and
enforces the frozen code taxonomy without importing, executing, or inspecting
Rust implementation code.
`make conformance` runs the fixture and independence guards, Rust codec tests,
and locked Python oracle tests. Both implementations independently construct
and decode all 23 accepted vectors and reject all 26 negative vectors with the
same frozen codes.
