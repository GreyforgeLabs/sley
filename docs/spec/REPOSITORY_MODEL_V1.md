# Repository Model v1

Status: M0 normative draft.

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

Root comparison emits typed entity, type, signature, CFG, call, effect,
capability, contract, test, entry-point, and dependency deltas. Three-way merge
uses an exact common ancestor and accepts automatic composition only when
disjointness or deterministic composition is proven. Ambiguity yields a
canonical conflict object; text conflict markers do not exist.

Packs bind format, epochs, roots, objects, optional transactions/refs,
compression profile, and digest tree, with no host paths. Import verifies every
bound digest before any ref move. GC traverses every retained ref, tag, lease,
transaction, pack manifest, and protected root and fails closed on malformed
references. Timestamps never imply reachability.

Recovery accepts exactly the old complete state or the new complete state with
a valid receipt. Unreachable staged objects are permitted and later collectible.
