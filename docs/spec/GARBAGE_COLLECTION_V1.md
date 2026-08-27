# Garbage Collection and Retention v1

Status: S20-180 normative contract.

## Scope

S20-180 defines deterministic mark/report/collect behavior for immutable SCB1
objects. It consumes explicit retention facts; it does not create, mutate, or
authorize refs, tags, leases, transactions, pack manifests, protected-root
policy, or sessions.

The current conformance profile accepts exact S20-160 roots and a
schema-selected object verifier/reference resolver. S20-390 and S20-500 later
own transaction/ref mutation and must coordinate those mutations with the GC
exclusive-ownership contract. S20-370 later owns protected policy-root
governance. S20-540 later owns clone-equivalent pack manifests.

## Retention snapshot

A retention snapshot contains:

- typed anchors;
- an exact root catalog;
- no timestamp, filesystem age, Git fact, cache fact, model output, or debug
  metadata.

Anchor kinds are closed:

| Tag | Kind | Current meaning |
|---:|---|---|
| 1 | `ref` | caller-resolved retained ref target |
| 2 | `tag` | caller-resolved retained tag target |
| 3 | `lease` | caller-declared active lease target |
| 4 | `transaction` | caller-resolved retained transaction target |
| 5 | `pack_manifest` | caller-resolved retained pack roots/objects |
| 6 | `protected_root` | caller-declared protected root/object target |
| 7 | `session_pin` | caller-declared active session pin target |

Every anchor has a caller-owned opaque 32-byte identifier and one or more
targets. A target is exactly a `StateRoot` or an `ObjectId`. Anchor identity is
repository metadata and never enters a `StateRoot` or object ID.

The caller owns whether a ref, tag, lease, transaction, manifest, protected
root, or session pin exists and is retained. GC owns only strict resolution and
reachability. There is no expiry timestamp or age comparison in this API.

Anchor/target input order is normalized for reporting. Duplicate anchor keys
or duplicate targets within one anchor fail closed. Every root target MUST
resolve to one exact imported root in the catalog. Every direct object target
MUST resolve to a verified object in store inventory.

## Root and object closure

The root catalog MUST be unique, strictly importable through the selected
preserved StateRoot decoder, and dependency-closed. A retained root marks:

- every dependency root recursively;
- every entity-binding `ObjectId`;
- its contract-root `ObjectId`;
- its test-root `ObjectId`.

The current S20-160 root record's `PolicyRootId` is a distinct digest domain,
not an `ObjectId`, so GC does not reinterpret it as an object-store path.
S20-370 must supply any protected policy object as an explicit protected-root
object target or define its later storage traversal contract.

Each marked object is read through `ObjectStore`, which verifies path identity,
digest trailer, declared ID, size, and the caller-supplied canonical verifier.
The same schema-selected resolver returns its referenced `ObjectId` values.
Those references are traversed transitively. Unknown or malformed reference
shape fails `GC_OBJECT_REFERENCE_MALFORMED`; a missing referenced object fails
`GC_OBJECT_MISSING`.

## Store inventory

Inventory is derived only from final canonical paths:

```text
objects/scb1/<first-two-lower-hex>/<next-two-lower-hex>/<ObjectId-lower-hex>.scb1
```

Every directory and final entry MUST be a real directory or regular file, not
a symlink. Fan-out components and filenames MUST be exact lowercase hex and
MUST agree. Staging files, malformed names, unexpected depths, non-regular
entries, and foreign files under `objects/scb1` fail `GC_INVENTORY_INVALID`.
S20-150 recovery must remove valid stage remnants before GC.

Every inventory object is canonically read and verified during mark/report,
including deletion candidates. A corrupted unreachable object is not silently
deleted.

## Mark and dry-run report

Marking is deterministic and returns canonically sorted:

- examined `(anchor_kind, anchor_id)` keys;
- resolved retained roots;
- reachable objects;
- complete inventory objects;
- deletion candidates (`inventory - reachable`);
- aggregate inventory and candidate byte counts;
- decision: `dry_run`, `collected`, or `partial_delete_failure`;
- successfully deleted IDs and an optional failed ID for collect mode.

Dry-run is mandatory as a supported mode and performs no write, delete, lock,
or timestamp mutation. Any malformed anchor, root, dependency, object
reference, inventory entry, digest, or limit returns an exact machine error;
there is no partial successful plan.

## Collection and exclusive ownership

Collection reruns the complete dry-run-equivalent mark phase while holding an
exclusive GC guard for the exact store root. A guard is acquired by atomic
exclusive creation of a store-root lock file and prevents concurrent GC runs.
Acquiring the guard is a witness that the caller has already stopped all
repository mutations. It cannot by itself stop code that ignores repository
locking; S20-390 and S20-500 MUST integrate object promotion and accepted-state
movement with this ownership boundary before concurrent repository mutation
exists.

Collection deletes only canonical final object paths present in the verified
inventory and absent from the complete reachable set. Immediately before each
delete it rereads and reverifies the object. It syncs the containing directory
after deletion. A crash can leave fewer unreachable objects deleted than the
plan, but cannot make a reachable object a candidate. Re-running collection is
idempotent.

If file deletion or directory sync fails, collection stops and returns
`GC_DELETE_IO` with a partial report listing completed deletions and the failed
object. It never reports `collected` after a partial host failure. Guard-file
recovery after process death requires explicit exclusive operator/repository
recovery authority and is not inferred from lock age.

## Closed limits

- anchors: `65,536`;
- targets per snapshot: `262,144`;
- root catalog entries: `65,536`;
- root dependency edges: `1,000,000`;
- traversed object-reference edges: `1,000,000`;
- inventory objects: `262,144`;
- bytes per object: SCB1 epoch-1 `67,108,864`;
- report ID entries across all lists: `786,432`;
- GC-owned allocation budget: `134,217,728` bytes, excluding caller input and
  one bounded object record under active verification.

Limits are checked before capacity allocation where an encoded or filesystem
count is attacker-controlled. A future epoch may tighten but never silently
loosen the selected contract.

## Stable failures

- `GC_RESOURCE_LIMIT`
- `GC_ANCHOR_MALFORMED`
- `GC_ANCHOR_UNRESOLVED`
- `GC_ROOT_MISSING`
- `GC_ROOT_INVALID`
- `GC_DEPENDENCY_MISSING`
- `GC_OBJECT_REFERENCE_MALFORMED`
- `GC_OBJECT_MISSING`
- `GC_INVENTORY_INVALID`
- `GC_DRY_RUN_REQUIRED`
- `GC_EXCLUSIVE_LOCK_REQUIRED`
- `GC_DELETE_IO`
- `GC_REACHABILITY_VIOLATION`
- `GC_INTERNAL_INVARIANT`

Exact lower-layer `SCB_*`, `STORE_*`, `STATE_ROOT_*`, and `SCHEMA_*` symbols
are preserved where those layers reject bytes. GC-specific relationship and
filesystem-layout failures use `GC_*`.

## S20-180 acceptance

- every anchor kind retains its root/object closure;
- roots retain dependency roots transitively;
- schema-selected object references retain child objects transitively;
- unordered snapshot input yields byte-for-byte equivalent sorted reports;
- missing/malformed roots, dependencies, references, inventory paths, and
  objects fail closed before deletion;
- dry-run reports exact reachable/inventory/candidate sets without mutation;
- collection under the exact guard deletes only verified unreachable objects,
  syncs directories, preserves every retained reconstruction, and is
  idempotent;
- a guard for a different store and concurrent guard acquisition fail closed;
- injected delete/sync failure returns a partial error report and never a false
  collected decision;
- API/dependency review confirms there is no timestamp, Git, path-age, model,
  cache, ref-mutation, transaction-mutation, or policy-authority input;
- T40 graph/pin/lease properties pass with assertion-effective seeds.
