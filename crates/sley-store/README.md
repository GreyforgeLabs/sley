# sley-store

`sley-store` persists immutable SCB1 standalone object records for Sley 2.

The store derives every final path from the lowercase hexadecimal `ObjectId`:

```text
objects/scb1/<hex[0..2]>/<hex[2..4]>/<64-hex-object-id>.scb1
```

Callers provide the canonical SCB1 verifier for the selected schema epoch. The
store runs that verifier before staging, after rereading the staged file, and
after promotion. The store also independently enforces the digest trailer,
declared ID, and path-derived ID checks.

The store guarantees stage-write-sync-reread-verify, atomic no-overwrite
promotion on the same filesystem, same-object idempotence, final-path
verification before success, bounded reads at the SCB1 epoch limit, and recovery
of store-owned staging files with `RECOVERY_STAGED_OBJECT` events.

The configured store root must already exist as a real directory. Each missing
fan-out component is created individually and its parent directory is synced;
concurrent exclusive stage-name collisions are retried without overwrite.

Staging recovery is a startup operation: its caller must hold exclusive
ownership of the store root while recovery runs. This crate deliberately does
not invent the cross-process repository lock that later transaction packages
must define. Recovery reports are sorted by relative staging path, and bounded
object reads reject symlinks and non-regular files.

It does not own schema semantics, policy, transactions, refs, packs, reachability,
garbage collection, quarantine, repair, deployment, or derived caches.
