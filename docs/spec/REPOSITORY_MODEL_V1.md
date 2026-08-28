# Repository Model v1

Status: M0 normative model with the S20-500 native branch/ref contract drafted
for independent review.

A Sley repository contains immutable objects, schema epochs, protected policy
roots, refs, a transaction DAG, pack manifests, pins/leases, and derived lock,
recovery, and cache metadata. Git may transport packs and version this Rust
implementation but defines no Sley identity or semantics.

A `StateRoot` binds exactly workspace identity, schema epoch, the canonically
sorted entity-binding table, entry points, dependency roots, contract root,
test root, protected policy-root reference, and epoch-declared interpretation
flags. It excludes ref names and heads, branch names, transaction ancestry,
leases/pins, timestamps, filesystem paths, locks, caches, and Git metadata.
Thus identical semantic state under one epoch has one root regardless of the
repository path that produced it.

Refs map names to `TransactionId` and move only by compare-and-swap. Resolving a
transaction yields an ancestry-independent `StateRoot`. Branch creation records
the exact parent transaction/root, epoch, policy, dependencies, and ancestry.

S20-390 first provides one fixed durable `accepted` head as the atomic commit
visibility primitive. It is owned by `sley-txn`, is not caller-named, and does
not implement branches. S20-500 owns native named branch refs and bounded
ancestry operations on top of verified S20-390 transaction records.
`sley-repo` may depend on `sley-txn`; `sley-txn` does not depend on
`sley-repo`.

`NATIVE_REFS_BRANCHES_V1.md` freezes the S20-500 draft boundary. Canonical
lowercase ASCII branch names are embedded in strict branch/ref records but are
mapped to host paths only through a domain-separated digest. An immutable
origin record preserves the exact creation transaction/root/workspace/epoch/
policy/dependency facts. A mutable ref record binds that origin to one current
verified transaction. One refs lock serializes create, resolve, list, advance,
and restricted stage recovery. Named refs never create transactions or make
imported receipts authoritative.

The initial S20-500 profile permits idempotent creation and direct-parent
fast-forward CAS only. Delete, force movement, rename, symbolic refs, tags,
named-branch candidate commit, and pack exchange remain unavailable. This
avoids inventing ABA, retention, authority, or clone semantics before their
owning packages are frozen.

Root comparison emits typed entity, type, signature, CFG, call, effect,
capability, contract, test, entry-point, and dependency deltas. Three-way merge
uses an exact common ancestor and accepts automatic composition only when
disjointness or deterministic composition is proven. Ambiguity yields a
canonical conflict object; text conflict markers do not exist.

Packs bind format, epochs, roots, objects, optional transactions/refs,
compression profile, and digest tree, with no host paths. The S20-170 profile
in `REPOSITORY_PACK_V1.md` is uncompressed and root/object-only; it rejects
transactions, refs, and signatures until S20-540 defines clone-equivalent
exchange. Import verifies every bound digest before object promotion and every
ref move. GC traverses every retained ref, tag, lease, transaction, pack
manifest, and protected root and fails closed on malformed references.
Timestamps never imply reachability.

Recovery accepts exactly the old complete state or the new complete state with
a valid receipt. Unreachable staged objects and unreachable complete receipts
are permitted and later collectible. A visible head that cannot resolve and
verify its receipt, transaction core, state root, policy root, and object
closure fails closed and is never silently repaired to a guessed revision.

`GARBAGE_COLLECTION_V1.md` freezes the S20-180 retention snapshot, mark/report,
and guarded collection profile. The snapshot consumes explicit typed
ref/tag/lease/transaction/pack/protected-root/session-pin targets but does not
create or authorize those repository facts. No timestamp or path age can imply
retention. Later ref and transaction implementations must coordinate accepted
state movement with the exclusive GC ownership boundary.
