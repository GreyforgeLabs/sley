# Constitutional Anti-Goal Matrix

Status: M0 review contract

Each prohibition must remain mechanically testable or independently reviewable.

| Anti-goal | Enforcement surface | Acceptance evidence |
|---|---|---|
| Sley source syntax or parser | dependency/file inventory; protocol input corpus | no parser crate/grammar/`.sley`; source-like input rejected |
| canonical text or human projection | format and release inventory | SCB1 only; debug notation rejected as input |
| formatter, REPL, Tree-sitter, conventional LSP | package and command inventory | release-check denylist is empty |
| Sley 1.x compatibility | dependency and fixture review | no legacy crate/source dependency; importer absent from GA graph |
| wholesale legacy copy | provenance and similarity review | disposition ADR for every reused concept; clean-room review |
| source/file/line/comment identity | schema review and hash properties | identity unchanged by derived labels/debug facts |
| human readability optimization | schema/benchmark review | no readability metric or textual review gate |
| opacity as security | threat model and independent decoder | public specs/oracle still satisfy all security tests |
| model/reviewer as semantic oracle | dependency and candidate tests | deterministic kernel alone decides validity |
| self-authorizing candidate | policy/epoch/oracle isolation tests | candidate cannot change its judging roots |
| normalize malformed bytes | SCB1 rejection corpus | every non-canonical vector rejected, not rewritten |
| weak/unknown success | error contract and fault injection | unknown/internal/incomparable never commits |
| arbitrary shell | opcode/adapter inventory and runtime denial | no process opcode or unrestricted adapter |
| mandatory Greyforge dependency | Cargo graph and clean-room release | core builds/tests offline without ZJX/Siglum/Forge products |
| Git-defined semantics | repository conformance | identical packs/roots outside Git; no Git metadata in hashes |
| native/JIT/AOT/marketplace/self-hosting before GA | workspace/package denylist | absent from GA dependency graph |
| network-dependent core tests | network-isolated gate | core/conformance pass with network disabled |
| unsafe code hidden in kernel | workspace lints and source scan | `unsafe_code=forbid`; any exception isolated by ADR/review |
| untyped or ambient effects | checker and adapter negative corpus | all effect/capability requirements structurally visible |
| hidden exceptions/null/implicit numeric conversion | type/VM corpus | exact typed failure and conversion rejection |
| human approval as language semantics | schema and capability review | machine policy/capability is sufficient; UI policy external |
| source-based merge | merge contracts | typed delta/conflict objects; no text markers |
| failed-trial erasure | benchmark manifest accounting | every attempted trial present in denominator |
| premature superiority or GA claim | dossier decision gate | Section 22 evidence complete before PASS |
| unauthorized release/deploy/spend | repo policy and operator gate | public source mirror allowed; no tag/package/release/deploy action |
