# S20-700 Object-Store Symlink Slice

Status: bounded landed-surface slice; **full S20-700 remains incomplete**

The S20-150 contract requires a real configured root and real object fan-out
directories. Existing tests rejected a symlink at the final object path but did
not directly assert the earlier root and fan-out boundaries.

The Unix-only regression covers three configurations:

- the configured store root is a symlink to another directory;
- `objects` is a symlink to another directory;
- `objects/scb1` is a symlink to another directory.

For every configuration, valid-object `put`, object `read`, and staged recovery
must return `STORE_IO`. No final object may be promoted and the symlink target
directory must remain empty. The test uses only temporary local directories and
performs no external filesystem or runtime mutation.

Focused validation:

```text
cargo test -p sley-store store_root_and_fanout_symlinks_fail_closed --locked
python3 scripts/check_object_store_spec.py
make adversarial
```

This is a behavioral confinement regression, not a persistent fuzz harness or
full S20-700 result. Non-Unix platforms still compile the crate but do not run
the Unix symlink fixture.

Vulcan's independent review found no open P0, P1, or P2 issue and confirmed the
path-confinement and no-outside-write assertions. Cross-platform behavior was
source-inspected only; the symlink fixture executed on Unix.
