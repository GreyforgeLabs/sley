# SCB1 Specification and Conformance

Status: S20-100 normative specification and S20-130 independent oracle complete;
S20-120 Rust codec pending.

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
  six unit tests, independent source-dependency check, encode/decode agreement
  on all 23 accepted vectors, and exact error-code agreement on all 26 rejected
  vectors.
- Vulcan S20-130 review: PASS with no P0/P1 findings. Its one P2 portability
  advisory was resolved by replacing the depth-65 generator marker with the
  complete 129-byte rejected input in the frozen corpus.

`scripts/check_scb1_spec.py` remains the fixture-construction/checksum guard.
The separately locked `oracle/scb1` package constructs and decodes accepted
bytes, hashes and verifies the standalone envelope, parses rejected inputs, and
enforces the frozen code taxonomy without importing, executing, or inspecting
Rust implementation code.
`make conformance` runs both guards and the oracle tests. Cross-implementation
agreement remains pending until S20-120 supplies the Rust codec.
