# Sley 2 — Machine Genesis

Sley 2 is a new, incompatible programming-system lineage in which programs are
created, stored, changed, executed, tested, versioned, and exchanged as typed
semantic state. Its canonical program form is SSMC1, its canonical encoding is
SCB1, and its machine interface is SMP1.

The governing doctrine is: **machines do not write source; they mutate verified
program state**. This repository therefore contains no Sley source parser,
canonical text format, formatter, conventional LSP, or compatibility promise
for Sley 1.x.

## Current phase

Phase M0 is complete. M1 packages S20-100 through S20-170 now provide SCB1,
typed identifiers, an independent oracle, schema epochs, the immutable object
store, deterministic state roots, and uncompressed root/object repository
packs. S20-180 and the scoped M1 core/adversarial/fuzz-smoke profiles now pass.
M2 is in progress: S20-200 freezes the SSMC1 entity/opcode schema and S20-210
implements the deterministic core type system. S20-220 now provides bounded,
deterministic CFG and value-use validation, and S20-230 adds exact least-fixed-
point effect closure with static scope typing. S20-240 now enforces a restricted
epoch-1 contract/test profile and deterministic policy-incomplete test planning;
its full-GA schema gaps remain explicit. S20-250 now adds deterministic
TypeDef/Function semantic fingerprints, a domain-separated canonical value
hash, and exact impact relationships for the twelve modeled semantic-core
kinds. Its six unmodeled entity bodies remain an explicit full-GA blocker.
S20-260 now provides a restricted deterministic O0 lowering profile for all
five terminators and the three validated Boolean opcodes, with exact derived
bytes and a root/profile-bound cache key. The other 52 opcode signatures,
generics, and adapters remain fail-closed gaps. S20-270 now executes that
restricted bytecode deterministically with exact Boolean semantics, all five
terminators, bounded fuel/value/output/cancellation behavior, and a canonical
observation digest. S20-280 now adds eight restricted deterministic,
request-owned reference adapter fixtures with exact identity, state, replay,
limit, atomicity, and transcript rules. VM adapter opcodes, live host access,
protected capabilities, live cancellation, and persistent report semantics
remain explicit gaps. S20-290 now provides restricted derived execution/test
report envelopes that verify VM observations and compare selected expectations
without claiming canonical persistence, policy/resource finality, test pass,
or the M2 exit. S20-300 now adds a restricted `SLEYIDX1` index-snapshot
conformance profile whose candidate records can match only an already-fresh
explicit modeled-request rebuild. It provides no trusted cache hydration,
root-provenance proof, query authority, or full S20-300/M3 completion. S20-310
now adds four restricted typed queries over opaque freshly derived
snapshots, with exact QueryId/response records and hard failure when limits
would omit facts. It does not claim the nineteen root-backed query classes,
truncation/continuation, capsules, SMP1, full S20-310, or M3 completion. S20-320
now adds a separately identified restricted evidence capsule for those complete
responses, with exact raw-ID dictionaries and direct-edge tables but fixed
no-omission, no-truncation, and no-continuation status. It is not the master
context capsule and adds no workspace/root/session authority. Every next
package must follow `docs/WORK_PACKAGES.md`. S20-330 is deliberately deferred
until negotiated session and verified workspace/root authority exist. S20-340
now generates immutable mutation descriptors for all eighteen SSMC1 entity
kinds and all sixteen primitive classes from the exact frozen manifest. It
provides no candidate construction, executable mutation, validation, policy,
session, commit, or transaction authority. The first decomposed S20-350 slice
now generates closed proposal-only host values for all eighteen entity bodies
and all seventy-five body fields, with no runtime type-name dispatch. A second
slice binds all 179 immutable descriptors to exact closed body/field
discriminants and performs type-selection-only admission. A strict low-level
SCB value cursor now exposes the already-frozen primitive decoder behavior for
later private codec work, including lossless strict 128-bit integer primitives;
it selects no schema or mutation type. A crate-private mutation layer now closes
primitive values, IDs/roots, direct enums, ordered lists/options, canonical
entity-ID sets, and the complete twenty-variant recursive `TypeExpr` family
with depth and allocation budgets. Further private slices close `MemberId`,
value/function references, immediates, CFG edges/cases, trap codes, the four
non-Option terminator records, and the dependency-closed `TypeParameterDef`,
`RecordField`, `BuiltinFailureValue`, `ContractSource`, `ContractBinding`, and
`ResourceLimits` manifest helpers. A bounded body slice also closes the exact
six-field `OperationBody` record. A second dependency-closed body slice covers
`WorkspaceBody`, `PackageBody`, `FunctionBody`, `ParameterBody`,
`GlobalValueBody`, `EffectDefBody`, `AdapterImportBody`, `EntryPointBody`,
`PolicyBindingBody`, and `DependencyBindingBody`. The native S20-350 codec now
closes the remaining seven bodies, all seventy-five descriptor-selected fields,
generic `Option<T>`, both terminator layers, `ConstValue`, the contract/test
families, aggregate entity values, bound preconditions, the exact validation
profile, and the thirteen-field candidate record. Its public proposal API can
build and import a digest-trailed `SLEYCAN1` candidate while checking contiguous
ordinals, exact generated descriptor selection, same-ordinal preconditions,
deterministic creation IDs, expiry shape, and the frozen validation-profile ID.
It performs no semantic validation, authority judgment, state mutation, commit,
I/O, or clock read.

Independent conformance now combines the retained 126-accepted/18-rejected
mutation-value corpus with a supplemental 44-accepted/4-rejected value corpus
and 1-accepted/14-rejected candidate corpus. Together they cover all eighteen
bodies, all seventy-five fields, all sixteen `ConstData` variants, all five
terminators, all sixteen mutation classes, preconditions, the candidate record,
the envelope, and digest rejection. Rust consumes the Python-produced bytes and
exact error codes. A two-lane production libFuzzer target independently drives
raw record decode/re-encode and stored candidate import/rebuild. S20-350 is
complete as a proposal-only construction boundary. S20-370 now
adds a separately registry-authorized protected policy root with exact opaque
principals, principal-specific grants, protected entity bindings, and mandatory
test/contract finalization. It has no authenticated policy-transition,
candidate, commit, or live runtime authority. S20-380 now adds a narrow
local-only capability-token profile with exact root/effect/scope/adapter/budget
binding, keyed BLAKE3 authentication, caller-owned replay/budget ledger
judgment, and an authorized reference-adapter wrapper. VM adapter opcodes,
candidate admission, commit, sessions, live host confinement, policy
transitions, providers, deployment, and GA remain explicit gaps.
S20-345 froze the candidate/value/precondition/capability-summary/validation-
profile/expiry contracts as proposal-only specifications. The freeze itself
added no builder or authority; S20-350 now implements the conforming builder
and decoder. It still adds no semantic validation, root construction, state
mutation, or commit path.
S20-710 now has a deterministic offline pre-release dependency inventory and a
bounded high-confidence secret scan. Those local checks do not complete the
package: operator-approved proprietary root license text, a standards SBOM,
release provenance, a release-candidate history re-anchor, and final Argus and
Vulcan dispositions remain mandatory.
S20-700 has one bounded incremental schema-import slice: 512 deterministic
inputs and an exact registry no-fallback test. It is not a persistent fuzz
harness. A second bounded regression proves authorized adapter state-root,
effect, and adapter binding confusion fails before ledger charge or fixture
mutation. A third Unix-only regression rejects symlinked object-store roots and
fan-out directories across put, read, and recovery without writing outside the
store. A fourth bounded mutation-value slice exercises all 126 currently
supported accepted fixtures through 252 trailing-byte and 446 distinct proper-
prefix mutations with panic containment and deterministic errors, while the 18
committed rejection vectors retain exact codes. That older bounded slice stays
as regression evidence; the independent supplemental corpus and candidate
target cover the newly completed proposal surface. These slices do not complete
the required cross-surface adversarial suite. Nine honest persistent targets
now exercise ten required surfaces: SCB1, schema bootstrap, repository-pack
import, typed S20-210, typed graph and CFG judgments, restricted queries,
restricted VM inputs, restricted adapter responses, and mutation candidates.
The pack target has a direct-input lane and a
rehashed-trailer lane that reaches beyond the outer digest check while
preserving failed-preflight no-write assertions. The typed semantic and query
targets use bounded fuzz-only constructors, not parallel canonical decoders or
the private mutation codec. Their 512-node type budget retains minimized
harness-OOM input `S20-700-HARNESS-001` as a closed regression. The scoped
`*-persistent-fuzz-smoke` Make targets use installed Clang/nightly runtimes,
generate deterministic fixture-derived or synthetic corpora as documented,
and record runtime evidence under `evidence/runtime/`. The matching runners
document their manual indefinite-run form.

## Authority

- Product goal: `<LOCAL_HOME>/machineresearch/sley/in-progress/2.0/Sley2.0mastergoal.md`
- Local architecture: `ARCHITECTURE.md`
- Security and threat register: `SECURITY.md`
- Normative drafts: `docs/spec/`
- Work-package DAG: `docs/WORK_PACKAGES.md`
- Evidence dossier: `machineresearch/sley-2.0/`

The product goal controls when this repository disagrees with a local draft.

## Authority boundaries

This repository is local-only. No push, tag, upload, deployment, publication,
provider spend, or public claim is authorized. Sley 1.2 deployment and release
work belongs to a separate session and repository worktree.

## Validation

`make quick` and `make check-changed` validate the implemented M0/M1 and
current M2 type-system/CFG/effect/restricted-contract/fingerprint/lowering/
execution/reference-adapter/report-envelope/index-snapshot/restricted-query/
restricted-capsule/mutation-schema/protected-policy-root/capability-token
surface, the closed mutation proposal host model, plus the offline S20-610
raw-baseline evidence contract and bounded
S20-710 pre-release audit (`DEFERRED`, never release `PASS`). Later profiles
are present but intentionally fail closed until their corresponding work
packages land.
`make v2` remains the eventual authoritative full gate.
