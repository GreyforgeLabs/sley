# Sley 2 Work-Package DAG

Status: M0 refined dependency and ownership baseline

One package has one accountable owner. Reviewers do not share write ownership.
“Gate” names the smallest focused validation; broader gates run only at the
subsystem and release boundaries described below.

| ID | Depends on | Owner | Owned paths/crates | Contracts | Primary risk | Acceptance | Focused gate | Release implication |
|---|---|---|---|---|---|---|---|---|
| S20-000 | — | Codex | external legacy archive; dossier 01 | freeze manifest | mutable/missing evidence | exact commit, binary hash/size, source snapshot and inventory verified | archive hash + manifest check | M0/M5 blocker |
| S20-010 | 000 | Codex | repository root | toolchain/workspace | false implementation claim | independent Git history, pinned Rust, M0 quick gate | `make quick` | M0 blocker |
| S20-020 | 000 | Codex | dossier 01/23 | disposition record | legacy plans revived implicitly | 1.2.1–1.2.4 explicitly superseded, retained | dossier consistency | M0 blocker |
| S20-030 | 010 | Codex | root docs; `docs/adr`; security | constitution/threat register | anti-goals not enforceable | every prohibition mapped to test or review | `make quick` + Ariadne/Nabu review | M0 blocker |
| S20-040 | 000 | Codex | `bench/corpus`; dossier 04/17 | benchmark manifest | biased/cherry-picked corpus | frozen tasks, arms, controls, denominators, oracle | manifest/schema check | M5 blocker |
| S20-100 | 030 | Ariadne | `docs/spec/SCB1.md` | SCB1 | ambiguous encoding | exact preimages, limits, canonical rules and vectors specified | spec lint + review | M1 blocker |
| S20-110 | 100 | Merlin | `sley-id` | identifier vectors | domain collision/ID reuse | every ID preimage/domain frozen; tombstone collision tests | id unit/property | M1 blocker |
| S20-120 | 100,110 | Merlin | `sley-canon` | SCB1 object | permissive decoder | encode/decode and rejection corpus pass without normalization | canon unit/property/fuzz-smoke | M1 blocker |
| S20-130 | 100 | Codex | `oracle/scb1` | SCB1 vectors | shared-bug oracle | structurally independent codec agrees byte-for-byte | oracle conformance | M1 blocker |
| S20-140 | 120 | Merlin | `sley-schema` | epoch/migration | downgrade/confusion | exact registry, old decoder preservation, migration skeleton | schema conformance | M1/M2 blocker |
| S20-150 | 110,120 | Merlin | `sley-store` | object record | corruption/partial persistence | immutable write/verify/promote and tamper detection | store unit + fault tests | M1 blocker |
| S20-160 | 140,150 | Merlin | `sley-store`,`sley-id` | state root | ordering/ancestry leak | order-independent bindings yield exact root | root property tests | M1 blocker |
| S20-170 | 150,160 | Merlin | `sley-store`,`sley-repo` | repository pack | malformed/host-bound pack | export/import clean store reconstructs exact root | pack conformance | M1/M4 blocker |
| S20-180 | 150,160 | Merlin | `sley-store`,`sley-repo` | GC report/pins | reachable deletion | dry-run and GC preserve all roots/leases | reachability property | M4 blocker |
| S20-200 | 030,140 | Ariadne | `docs/spec/SSMC1.md`; schema inputs | SSMC entities/opcodes | syntax artifacts/semantic ambiguity | complete typed entity/opcode contracts, no source path | spec/schema review | M2 blocker |
| S20-210 | 200 | Merlin | `sley-ssmc`,`sley-check` | type contracts | implicit/host-dependent typing | core type positive/negative corpus deterministic | type unit/property | M2 blocker |
| S20-220 | 200,210 | Merlin | `sley-ssmc`,`sley-check` | graph/CFG result | nontermination/use error | dominance, edges, uses, reachability reject malformed graphs | CFG corpus + fuzz-smoke | M2 blocker |
| S20-230 | 210,220 | Merlin | `sley-ssmc`,`sley-check` | effect closure | hidden ambient authority | exact declared effect closure and scope | effect corpus/property | M2/M3 blocker |
| S20-240 | 210,220,230 | Merlin | `sley-ssmc`,`sley-check` | restricted epoch-1 contract/test profile | prose or weak oracle | pure function predicates/tests validate; ambiguous kinds/environments fail closed; provisional selection is deterministic and policy-incomplete | restricted contract/test corpus | M2 blocker; full GA requires later schema epoch |
| S20-250 | 200,230 | Merlin | `sley-ssmc`,`sley-query` | restricted epoch-1 fingerprint/impact profile | label/layout sensitivity or incomplete edges | TypeDef/Function equivalence shares fingerprints; modeled kinds 4–15 yield exact edges; unmodeled kinds fail closed | fingerprint/impact property | M3/M4 input only; complete-root consumers remain blocked |
| S20-260 | 210,220 | Merlin | `sley-vm` | restricted epoch-1 O0 derived bytecode | lowering changes meaning or copies unchecked opcode semantics | validated CFG lowers all terminators and validated Boolean opcodes deterministically with exact bytes/cache key; unsupported semantics fail closed | restricted lowering conformance | M2 input only; full lowering requires complete opcode judgment |
| S20-270 | 250,260 | Merlin | `sley-vm` | restricted epoch-1 deterministic execution outcome | host/resource/cache divergence | integrated restricted lowering executes Boolean ops/all terminators with exact fuel, limits, value, and observation digest; raw bytecode and unsupported semantics fail closed | restricted VM corpus/property | M2 input only; full VM and report entities remain blocked |
| S20-280 | 230,270 | Merlin | `sley-adapter`; `sley-vm` integration deferred | restricted epoch-1 request-owned adapter fixture protocol | ambient escape/impersonation/replay injection | eight deterministic fixture kinds enforce exact identity/types/schema-bound state, budgets, canonical paths, replay order, and atomic mutation; adapter/effect VM execution stays fail closed | restricted adapter adversarial/property | M2 security input only; full GA requires VM/policy/capability/live-confinement packages |
| S20-290 | 240,270 | Merlin | `sley-conformance`; minimal `sley-vm` observation export | restricted derived execution/test envelopes | nondeterministic or overstated evidence | exact observation-linked envelopes and expectation comparisons are versioned/digested; policy/resource finality, canonical entities, persistence, test pass, and M2 exit fail closed | restricted report conformance | M2 evidence input only; full exit requires report schema/persistence/policy/resource completion |
| S20-300 | 250 | Merlin | `sley-query` | restricted epoch-1 index snapshot; complete-root profile deferred | cache becomes authority | modeled-request indexes reproduce exactly; candidate bytes are privately bounded, discarded safely, and admitted only after a fresh byte-equal rebuild | restricted index rebuild/admission property | M3 evidence input only; full blocker remains six entity bodies plus strict root/object extraction and useful safe cache reuse |
| S20-310 | 300 | Merlin | `sley-query` | restricted modeled-snapshot typed queries; full root-backed engine deferred | query explosion/hidden omissions | four closed queries bind exact snapshot/context/limits, return canonically ordered complete payloads, and hard-fail before partial output | restricted query unit/adversarial | M3 evidence input only; all nineteen root-backed classes plus continuation/capsules remain blockers |
| S20-320 | 310 | Merlin | `sley-query` | context capsule | hidden omitted facts | dictionaries, limits, omissions, continuation and digest exact | capsule conformance | M3/M5 blocker |
| S20-330 | 320 | Merlin | `sley-query`,`sley-protocol` | session handle | cross-root reuse | handles fail after session/root/epoch change | stale-handle tests | M3 blocker |
| S20-340 | 140,200 | Merlin | `sley-schema`,`sley-mutate` | mutation schema | handwritten drift | generated typed operations reproduce schema digest | generated drift check | M3 blocker |
| S20-350 | 340 | Merlin | `sley-mutate` | candidate/preconditions | underbound candidate | exact base/policy/capability/preimage bindings and digest | candidate unit/property | M3 blocker |
| S20-360 | 220,230,240,350,370,380 | Merlin | `sley-check`,`sley-mutate`,`sley-policy` | candidate result | phase bypass/state mutation | ordered monotonic phases include protected policy/capability judgment; invalid candidates leave state unchanged | candidate adversarial | M3 security blocker |
| S20-370 | 160,230 | Merlin | `sley-policy` | policy | self-authorization | separate protected root and mandatory test rules | policy isolation tests | M3 security blocker |
| S20-380 | 280,370 | Merlin | `sley-policy`,`sley-adapter` | capability token | forgery/replay/scope escape | authenticated root-bound exact-scope tokens enforced twice | capability adversarial | M3 security blocker |
| S20-390 | 150,160,360,370 | Merlin | `sley-txn`,`sley-store` | transaction/receipt | partial/stale commit | recheck, durable object/receipt, ref CAS, exact receipt | transaction fault tests | M3/M4 blocker |
| S20-400 | 310,350,390 | Ariadne | `docs/spec/SMP1.md`; protocol schemas | handshake/methods/errors | transport-owned semantics | all families/version/limits/codes frozen | protocol spec review | M3 blocker |
| S20-410 | 400 | Merlin | `sley-protocol` | SMP1 frame | allocation/request confusion | strict length/SCB frame and deterministic server | framing conformance/fuzz | M3 blocker |
| S20-420 | 400,410 | Merlin | `sley-json-bridge` | generated JSON | collapsed codes/private rules | round-trip fixtures; zero semantic validation | bridge drift/conformance | M3/M5 input |
| S20-430 | 410 | Merlin | `sley-cli` | CLI report | duplicated semantics | wrapper only; all judgment from protocol | dependency/rule audit | M3/M5 input |
| S20-440 | 410 | Merlin | `sley-protocol` | cancel/stream/limits | bypass/leak | bounded cancel, streaming continuation, hard limits | protocol adversarial | M3 exit |
| S20-500 | 390 | Merlin | `sley-repo` | ref/branch | ancestry/ref race | exact parent bindings and CAS refs reconstruct | repo property tests | M4 blocker |
| S20-510 | 250,500 | Merlin | `sley-repo` | semantic comparison | missed collateral change | complete typed deltas for all canonical entity classes | comparison corpus | M4 blocker |
| S20-520 | 510 | Merlin | `sley-repo` | merge/conflict | silent choice/lost change | disjoint merge deterministic; ambiguity becomes object | merge properties/adversarial | M4 blocker |
| S20-530 | 390,500 | Vulcan | `sley-store`,`sley-txn`,`sley-repo` tests | recovery report | partial accepted state | every durability interruption yields old or complete new state | crash matrix | M4 blocker |
| S20-540 | 170,500 | Merlin | `sley-repo`,`sley-conformance` | pack exchange | clone divergence | clean import reconstructs root, refs, ancestry per profile | clone-equivalent test | M4 exit |
| S20-600 | 000,040 | Codex | `bench/legacy` | legacy trial | legacy mutation/contamination | frozen artifact only, exact environment and failures retained | runner smoke + hash check | M5 blocker |
| S20-610 | 040 | Codex | `bench/raw` | raw trial | unequal tools/context | same model/budget/oracle controls enforced | runner smoke/control audit | M5 blocker |
| S20-620 | 320,420,430 | Codex | `sley-bench` | Sley2 trial | privileged context | capsule/affordance-only agent arm and complete trace | runner smoke/control audit | M5 blocker |
| S20-630 | 600,610,620 | Codex | `sley-bench`; dossier 16-18 | accounting | hidden tokens/failures | ACT/context/repairs derived from immutable trial manifests | accounting property | M5 blocker |
| S20-640 | 630 | Codex | benchmark evidence | trial set | underpowered/cherry-picked runs | frozen small/large model trials, all attempts counted | statistical/replay audit | succession blocker |
| S20-650 | 040 | Codex | `bench/external` | optional external trial | unfair/unavailable comparison | exact version/environment or explicit unavailable state | control audit | public-claim only |
| S20-700 | affected package | Vulcan | `fuzz/`; adversarial fixtures | finding record | shallow green suite | persistent targets, minimized regressions, fault seeding | adversarial + fuzz-smoke | every phase/GA blocker |
| S20-710 | 010 | Argus | lockfile/SBOM/license/secret evidence | audit report | substitution/secrets/license | pinned deps, inventory, scans, dispositions | supply-chain audit | GA blocker |
| S20-720 | all GA code | Prometheus | release scripts/dist | release manifest | source/path/debug leakage | clean-room artifact runs source-independent demo | release-check | M6 blocker |
| S20-730 | 720 | Codex | reproducibility/conformance evidence | provenance | irreproducible/substituted build | second build plus independent codec/kernel evidence | reproducibility gate | M6 blocker |
| S20-740 | 730 | Vulcan | independent review dossier | finding register | unresolved architecture/security debt | complete PASS, no open P0/P1/P2 | independent review | M6 blocker |
| S20-750 | 640,740 | Codex | complete dossier/machine summary | decision record | premature GA/superiority | every Section 22/26 item evidenced; exact decision state | dossier audit + `make v2` | final local decision |

## Subsystem boundaries

- M0: 000–040 plus normative drafts and required Ariadne/Nabu review.
- M1: 100–180; run `quick`, `core`, `conformance`, `fuzz-smoke`.
- M2: 200–290; add semantic corpus, VM conformance, and adapter adversarial.
- M3: 300–440; add stale, policy, protocol, limit, and agent-loop E2E gates.
- M4: 500–540; add merge, GC, crash, and clone-equivalent gates.
- M5: 600–650; freeze controls before trials and preserve every failure.
- M6: 700–750; `make v2` and `release-check` are authoritative.

No package may begin merely because its code seems easy. Its dependencies must
have committed acceptance evidence, and its owner must have exclusive write
ownership of the listed paths for the slice.

The M0 `SMP1.md` is a constitutional interface draft needed to constrain early
architecture. S20-400 freezes the implementable protocol contract only after
query, mutation, and transaction schemas exist; it does not postpone the M0
draft. The refined dependency added S20-370 and S20-380 to S20-360 because a
“complete” validation pipeline cannot precede protected policy and capability
judgment.
