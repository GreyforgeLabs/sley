# sley-scb1

`sley-scb1` implements Sley Canonical Binary v1 primitive, structural, and
standalone-envelope encoding and decoding.

Decoding is strict: non-minimal integers, invalid UTF-8, non-canonical floats,
unordered fields or map keys, digest mismatches, and resource-limit failures
return stable `SCB_*` error codes instead of normalizing input.
