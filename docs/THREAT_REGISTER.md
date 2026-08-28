# Threat Register

Status: M0 planned-control map. Evidence paths are future required outputs and
must not be read as passing evidence until the named work package records them.

| ID | Threat | Sev | Owner | Expected failure code | Required test | Evidence path |
|---|---|---:|---|---|---|---|
| T01 | malformed SCB1 | P0 | sley-canon | `SCB_MALFORMED` | decoder fuzz/rejection | `evidence/security/T01/` |
| T02 | alternate noncanonical encoding | P0 | sley-canon | `SCB_NON_CANONICAL` | independent rejection vectors | `evidence/security/T02/` |
| T03 | object hash mismatch | P0 | sley-store | `SCB_DIGEST_MISMATCH` | one-byte corruption | `evidence/security/T03/` |
| T04 | object substitution | P0 | sley-store | `STORE_OBJECT_SUBSTITUTION` | wrong-object/preimage fault | `evidence/security/T04/` |
| T05 | schema downgrade | P0 | sley-schema | `SCHEMA_DOWNGRADE` | downgrade negotiation/import | `evidence/security/T05/` |
| T06 | schema epoch confusion | P0 | sley-schema | `SCHEMA_EPOCH_MISMATCH` | cross-epoch object matrix | `evidence/security/T06/` |
| T07 | duplicate logical identity | P0 | sley-id | `ID_DUPLICATE_ENTITY` | creation collision property | `evidence/security/T07/` |
| T08 | identity reuse after deletion | P0 | sley-id | `ID_REUSE_FORBIDDEN` | tombstone recreation | `evidence/security/T08/` |
| T09 | dangling reference | P0 | sley-check | `GRAPH_UNRESOLVED_REFERENCE` | reference negative corpus | `evidence/security/T09/` |
| T10 | hostile graph cycles | P0 | sley-check | `GRAPH_CYCLE_FORBIDDEN` | cyclic graph fuzz | `evidence/security/T10/` |
| T11 | pathological CFG | P0 | sley-check | `CFG_RESOURCE_LIMIT` | hostile CFG corpus | `evidence/security/T11/` |
| T12 | type-checker nontermination | P0 | sley-check | `TYPE_RESOURCE_LIMIT` | recursive-type/fuel fuzz | `evidence/security/T12/` |
| T13 | query explosion | P1 | sley-query | `QUERY_RESOURCE_LIMIT` | fanout/depth adversarial | `evidence/security/T13/` |
| T14 | truncation hides required facts | P0 | sley-query | `QUERY_REQUIRED_FACT_OMITTED` | truncation/validation independence | `evidence/security/T14/` |
| T15 | handle reuse across roots | P0 | sley-query | `SESSION_STALE_HANDLE` | root/session/epoch matrix | `evidence/security/T15/` |
| T16 | oversized mutation list | P1 | sley-mutate | `MUTATION_RESOURCE_LIMIT` | count/byte boundary | `evidence/security/T16/` |
| T17 | stale-root commit | P0 | sley-txn | `STALE_ROOT` | concurrent CAS scenario; restricted S20-390 coverage present | `evidence/validation/s20-390-atomic-commit-closeout-v1.json` |
| T18 | stale-entity commit | P0 | sley-txn | `STALE_ENTITY` | exact preimage mutation; restricted S20-360/S20-390 coverage present | `evidence/validation/s20-390-atomic-commit-closeout-v1.json` |
| T19 | candidate modifies own policy | P0 | sley-policy | `POLICY_SELF_MODIFICATION` | policy-isolation E2E | `evidence/security/T19/` |
| T20 | candidate modifies validator epoch | P0 | sley-schema | `SCHEMA_SELF_MODIFICATION` | epoch-isolation E2E | `evidence/security/T20/` |
| T21 | candidate weakens mandatory tests | P0 | sley-policy | `POLICY_ORACLE_SELF_MODIFICATION` | test-root isolation | `evidence/security/T21/` |
| T22 | capability forgery | P0 | sley-policy | `CAP_AUTHENTICATOR_INVALID` | token bit-flip/issuer matrix; S20-380 unit coverage present | `evidence/security/T22/` |
| T23 | capability replay | P0 | sley-policy | `CAP_REPLAY` | nonce/root/expiry replay; S20-380 unit coverage present | `evidence/security/T23/` |
| T24 | capability scope confusion | P0 | sley-policy | `CAP_SCOPE_MISMATCH` | workspace/effect/resource matrix; S20-380 unit coverage present | `evidence/security/T24/` |
| T25 | adapter impersonation | P0 | sley-adapter | `ADAPTER_IDENTITY_MISMATCH` | adapter ABI/identity swap | `evidence/security/T25/` |
| T26 | adapter response injection | P0 | sley-adapter | `ADAPTER_TYPE_MISMATCH` | typed replay outcome injection | `evidence/security/T26/` |
| T27 | path traversal | P0 | sley-adapter | `ADAPTER_PATH_INVALID` | traversal/separator/Unicode corpus | `evidence/security/T27/` |
| T28 | symlink escape | P0 | sley-adapter | `ADAPTER_SYMLINK_ESCAPE` | confined-root symlink matrix | `evidence/security/T28/` |
| T29 | environment leakage | P0 | sley-vm | `VM_AMBIENT_STATE_FORBIDDEN` | clean/poisoned env equivalence | `evidence/security/T29/` |
| T30 | output flooding | P1 | sley-vm | `VM_OUTPUT_LIMIT` | exact output ceiling | `evidence/security/T30/` |
| T31 | cancellation bypass | P1 | sley-vm | `VM_CANCELLED` | bounded cancel latency | `evidence/security/T31/` |
| T32 | fuel/memory bypass | P0 | sley-vm | `VM_RESOURCE_LIMIT` | nested/call/collection stress | `evidence/security/T32/` |
| T33 | VM nondeterminism | P0 | sley-vm | `VM_NONDETERMINISM_DETECTED` | repeated observation digests | `evidence/security/T33/` |
| T34 | floating host divergence | P0 | sley-vm | `VM_FLOAT_PROFILE_MISMATCH` | cross-build FP vectors | `evidence/security/T34/` |
| T35 | cache poisoning | P0 | sley-query | `CACHE_BINDING_MISMATCH` | root/epoch/policy key faults | `evidence/security/T35/` |
| T36 | derived index treated as canonical | P0 | sley-store | `STORE_DERIVED_INPUT_FORBIDDEN` | corrupt/delete/rebuild cache | `evidence/security/T36/` |
| T37 | crash during object write | P0 | sley-store | `RECOVERY_STAGED_OBJECT` | interruption matrix | `evidence/security/T37/` |
| T38 | crash during receipt write | P0 | sley-txn | `RECOVERY_RECEIPT_INCOMPLETE` | restricted S20-390 interruption matrix present | `evidence/validation/s20-390-atomic-commit-closeout-v1.json` |
| T39 | crash during accepted-head or later ref update | P0 | sley-txn, then sley-repo for S20-500 named refs | `RECOVERY_REF_CAS_INCOMPLETE` | restricted fixed-head S20-390 interruption matrix present; named refs pending | `evidence/validation/s20-390-atomic-commit-closeout-v1.json` |
| T40 | GC deletes reachable object | P0 | sley-store | `GC_REACHABILITY_VIOLATION` | graph/pin/lease property | `evidence/security/T40/` |
| T41 | malicious pack | P0 | sley-repo | `PACK_INVALID` | importer fuzz/corruption | `evidence/security/T41/` |
| T42 | decompression bomb | P1 | sley-repo | `PACK_DECOMPRESSION_LIMIT` | ratio/size boundary | `evidence/security/T42/` |
| T43 | merge loses change | P0 | sley-repo | `MERGE_CHANGE_LOSS` | delta preservation property | `evidence/security/T43/` |
| T44 | merge silently chooses conflict | P0 | sley-repo | `MERGE_CONFLICT_REQUIRED` | incompatible same-entity E2E | `evidence/security/T44/` |
| T45 | protocol downgrade | P0 | sley-protocol | `PROTOCOL_DOWNGRADE` | handshake matrix | `evidence/security/T45/` |
| T46 | request ID confusion | P0 | sley-protocol | `PROTOCOL_REQUEST_ID_CONFLICT` | duplicate/cross-session IDs | `evidence/security/T46/` |
| T47 | cross-workspace leakage | P0 | sley-protocol | `SESSION_WORKSPACE_MISMATCH` | two-workspace isolation | `evidence/security/T47/` |
| T48 | model-generated authority claim | P0 | sley-policy | `CAPABILITY_DENIED` | hostile label/prompt metadata | `evidence/security/T48/` |
| T49 | debug dump used as canonical input | P0 | sley-canon | `SCB_MAGIC_INVALID` | debug-notation input | `evidence/security/T49/` |
| T50 | Git metadata used as Sley state | P0 | sley-repo | `REPO_EXTERNAL_METADATA_FORBIDDEN` | Git-independent reconstruction | `evidence/security/T50/` |
| T51 | ZJX transport tampering | P0 | sley-repo | `PACK_DIGEST_MISMATCH` | decompress/tamper/import | `evidence/security/T51/` |
| T52 | dependency substitution | P1 | release | `RELEASE_DEPENDENCY_MISMATCH` | local lock/source/checksum inventory present; standards SBOM and release provenance pending | `evidence/security/T52/` |
| T53 | release artifact substitution | P1 | release | `RELEASE_ARTIFACT_MISMATCH` | manifest/hash verification | `evidence/security/T53/` |
| T54 | secret committed in fixtures | P1 | release | `RELEASE_SECRET_FINDING` | bounded high-confidence candidate/history scan present; release re-anchor, wider privacy review, and independent disposition pending | `evidence/security/T54/` |
| T55 | benchmark contamination/cherry-pick | P1 | sley-bench | `BENCH_CONTROL_VIOLATION` | manifest denominator/control audit | `evidence/security/T55/` |

P0/P1 evidence requires independent Vulcan disposition. A green test without a
fault-seeding or assertion-effectiveness check remains an open release finding.
