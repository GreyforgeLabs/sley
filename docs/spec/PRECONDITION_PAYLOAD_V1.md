# Bound Precondition Payload v1

Status: S20-345 normative contract freeze; evaluation deferred to S20-360.

Each candidate operation has exactly one `BoundPrecondition`, ordered by the
same contiguous ordinal as the operation:

| Tag | Field | Type |
|---:|---|---|
| 1 | operation_ordinal | `UInt32` |
| 2 | requirement | `PreconditionRequirement` |
| 3 | payload | `PreconditionPayload` selected by requirement |

The closed requirement/payload union is:

| Tag | Requirement | Payload record |
|---:|---|---|
| 1 | `ExpectedIdentityAbsent` | `entity_id:EntityId` |
| 2 | `ExactEntityVersion` | `entity_id:EntityId, object_id:ObjectId` |
| 3 | `ExactContainerVersion` | `container_id:EntityId, object_id:ObjectId, field_tag:UInt32` |

Requirement must equal the immutable S20-340 descriptor requirement. Entity
and container IDs must equal the operation target; a container field tag must
equal its ordered-child descriptor field. Creation absence binds the derived
ID but is not proof of absence; S20-360 checks both live and tombstone ledgers
under the exact base root.

The candidate's base root, base transaction, schema epoch, policy root,
capability summary, validation profile, and expiry are global preconditions
because they already enter the candidate digest. Validation must compare them
against authoritative context before entity-specific checks. No payload may
contain a claimed Boolean, timestamp observation, query result, session handle,
path, ref name, or mutable-latest reference.

Any missing, extra, duplicate, mismatched, or stale precondition rejects the
candidate without constructing a candidate root or changing state.
