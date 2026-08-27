# Candidate Record v1

Status: S20-345 normative contract freeze; no implementation or authority.

## Boundary

A candidate is an immutable, canonical proposal to transform one exact state.
Possessing, constructing, hashing, or decoding it grants no authority and
changes no state. S20-350 may construct this record only after implementing the
typed codecs frozen here. S20-360 must independently validate it; S20-390 alone
may durably commit a `VALID` result.

No field may contain source text, a path, a label used as identity, a session
handle, an opaque mutation payload, a Rust type name, a caller-asserted pass, a
capability secret/MAC, or executable host/provider instructions.

## Canonical envelope and identity

```text
candidate_preimage = "SLEYCAN1" || uvar(1) ||
                     len(candidate_record) || candidate_record
CandidateId = BLAKE3-256("sley2.candidate.v1" || candidate_preimage)
stored_candidate = candidate_preimage || CandidateId[32]
```

`candidate_record` is one canonical SCB1 Record. The digest trailer is the
master goal's candidate-digest field; the record does not contain its own
digest and therefore has no self-hash cycle.

| Tag | Field | Type | Rule |
|---:|---|---|---|
| 1 | format_version | `UInt32` | exactly `1` |
| 2 | workspace_id | `WorkspaceId` | exact target workspace |
| 3 | base_transaction_id | `TransactionId` | exact accepted parent |
| 4 | base_root | `StateRoot` | exact accepted semantic root |
| 5 | schema_epoch_id | `SchemaEpochId` | exact decoder/validator epoch |
| 6 | policy_root_id | `PolicyRootId` | protected root that must judge it |
| 7 | principal_id | `PrincipalId` | opaque identity reference only |
| 8 | capability_summary_digest | `CapabilitySummaryDigest[32]` | proposal binding, not proof |
| 9 | operations | `List<MutationOperation>` | nonempty, ordinal ordered |
| 10 | preconditions | `List<BoundPrecondition>` | one per operation |
| 11 | validation_profile_id | `ValidationProfileId[32]` | exact frozen profile |
| 12 | candidate_nonce | `CandidateNonce[32]` | identity/replay input |
| 13 | expiry | `CandidateExpiry` | exact half-open deadline |

Unknown, missing, duplicate, or out-of-order fields fail closed. Candidate
bytes are bounded by the selected validation profile and the S20-140
standalone-value ceiling. All thirteen fields enter `CandidateId`.

## Mutation operation

`MutationOperation` is the canonical Record:

| Tag | Field | Type |
|---:|---|---|
| 1 | ordinal | `UInt32` |
| 2 | class | `MutationClass` tags 1 through 16 from S20-340 |
| 3 | target_kind | `EntityKind` tags 1 through 18 |
| 4 | target_entity | `EntityId` |
| 5 | field_tag | `Option<UInt32>` |
| 6 | payload | `MutationPayload` selected by the exact descriptor |
| 7 | precondition_ordinal | `UInt32` equal to `ordinal` |

Ordinals are contiguous from zero and define semantic order. They are never
re-sorted by host iteration or encoded bytes. Descriptor lookup by
`(class,target_kind,field_tag)` must succeed in the exact generated S20-340
table before payload decode. The descriptor selects the only lawful payload
codec; a payload cannot select or describe its own type.

For class 1 `create entity`, `target_entity` must equal the S20-110 derivation
from workspace, candidate nonce, target kind, and the zero-based ordinal among
class-1 operations. Validation must collision-check live and tombstoned IDs.
Other classes target an already-bound logical identity.

`MutationPayload` is a closed union keyed by class tag:

| Tag | Class payload |
|---:|---|
| 1 | exact typed `EntityBody` selected by `target_kind` |
| 2 | exact typed replacement `EntityBody` |
| 3 | `Unit` |
| 4 | exact generated scalar-field value |
| 5 | exact generated field value |
| 6 | exact `EntityId` or `Option<EntityId>` selected by descriptor |
| 7 | `OrderedInsert(index:UInt32, child:EntityId)` |
| 8 | `OrderedRemove(index:UInt32, expected_child:EntityId)` |
| 9 | `OrderedMove(from:UInt32, to:UInt32, expected_child:EntityId)` |
| 10 | exact typed `EntryPointBody` |
| 11 | `Unit` |
| 12 | exact typed `TestCaseBody` |
| 13 | exact typed `TestCaseBody` |
| 14 | exact typed `ContractBody` |
| 15 | exact typed `ContractBody` |
| 16 | exact typed `DependencyBindingBody` |

Entity and field codecs are frozen by `MUTATION_VALUE_CODEC_V1.md`. A special
add/replace payload carries a body, never nested standalone-object bytes.

## Cross-field invariants

- workspace, root, epoch, and policy bindings must agree with the base
  transaction/root and authenticated validation context;
- principal and capability summary are comparisons against host-authenticated
  facts, never candidate-origin authority;
- each operation has exactly one same-ordinal precondition of the requirement
  named by its S20-340 descriptor;
- the profile and expiry must be recognized before deeper judgment;
- ordinary candidates cannot modify the bound policy root, schema epoch,
  validator/kernel, mandatory contract root, or mandatory test root;
- decode/import/build APIs expose no apply, commit, receipt, CAS, session,
  provider, network, process, or filesystem operation.

S20-345 freezes this record only. S20-350 remains blocked until independent
review confirms all referenced codecs and records are exact and implementable.
