# sley-scb1

`sley-scb1` implements Sley Canonical Binary v1 primitive, structural, and
standalone-envelope encoding and decoding.

Decoding is strict: non-minimal integers, invalid UTF-8, non-canonical floats,
unordered fields or map keys, digest mismatches, and resource-limit failures
return stable `SCB_*` error codes instead of normalizing input.

`ScbValueCursor` exposes the same strict low-level value reads for callers that
already know the expected shape: canonical varints, `ZigZag` `sint64`, booleans,
length-delimited bytes/text, canonical float bits, fixed bytes, bounded counts,
sized payloads, and union tag/payload pairs.
