# sley-scb1

`sley-scb1` implements Sley Canonical Binary v1 primitive, structural, and
standalone-envelope encoding and decoding.

Decoding is strict: non-minimal integers, invalid UTF-8, non-canonical floats,
unordered fields or map keys, digest mismatches, and resource-limit failures
return stable `SCB_*` error codes instead of normalizing input.

`ScbValueCursor` exposes the same strict low-level value reads for callers that
already know the expected shape: canonical varints through `read_uvar` and
`read_uvar128`, `ZigZag` `sint64`/`sint128`, booleans, length-delimited
bytes/text, canonical float bits, fixed bytes, bounded counts, sized payloads,
and union tag/payload pairs. Canonical 128-bit integer construction is available
through `encode_uvar128` and `encode_sint128`.
