# Query and Context Capsules

Status: S20-300/S20-310 restricted epoch-1 evidence implemented; full design
remains open.

S20-300 through S20-330 own derived indexes, typed bounded queries, explicit
omission/continuation, capsule digests, and root/session/epoch-bound handles.
`docs/spec/INDEX_SNAPSHOT_PROFILE_V1.md` and
`docs/spec/RESTRICTED_QUERY_PROFILE_V1.md` now freeze a modeled-request-only,
rebuild-first snapshot plus four exact hard-bounded query kinds. They provide
no root provenance, useful cache hydration, partial output, continuation,
capsule, handle, SMP1, or full M3 evidence.
