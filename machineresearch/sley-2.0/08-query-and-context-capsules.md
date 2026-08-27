# Query and Context Capsules

Status: S20-300/S20-320 restricted epoch-1 evidence implemented; full design
remains open.

S20-300 through S20-330 own derived indexes, typed bounded queries, explicit
omission/continuation, capsule digests, and root/session/epoch-bound handles.
`docs/spec/INDEX_SNAPSHOT_PROFILE_V1.md`,
`docs/spec/RESTRICTED_QUERY_PROFILE_V1.md`, and
`docs/spec/RESTRICTED_QUERY_CAPSULE_PROFILE_V1.md` now freeze a modeled-request-
only rebuild-first snapshot, four exact hard-bounded query kinds, and a
complete-response-only evidence capsule with raw-ID dictionaries. They provide
no root provenance, useful cache hydration, partial output, lawful omission or
continuation, master context capsule, handle, SMP1, or full M3/M5 evidence.
