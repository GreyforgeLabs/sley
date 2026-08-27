# SCB1 Specification and Conformance

Status: S20-100 normative specification complete; no codec or oracle exists.

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
  `525c6ec13b9f15d52237da94bf89221e0f22cbfb8a2fc6cffe410e22891dd055`;
- one complete stored envelope whose BLAKE3/ObjectId was generated with Rust
  `blake3` 1.8.2 and whose preimage, digest, and stored bytes are frozen;
- Ariadne review: PASS after the envelope/digest and all envelope-level
  rejection fixtures were added.

`scripts/check_scb1_spec.py` validates fixture construction and checksums but is
not the S20-130 independent oracle. The S20-120 Rust codec and S20-130 oracle
remain explicitly unimplemented.
