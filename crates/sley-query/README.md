# sley-query

`sley-query` owns derived, disposable semantic relationship indexes. S20-250
implements exact direct impact edges, their reverse index, bounded transitive
impact, and the checked `value_hash` entry point for the restricted epoch-1
profile. S20-300 adds a restricted `SLEYIDX1` snapshot record and rebuild-first
candidate admission: candidate bytes are never exposed as a queryable index and
can match only an already-fresh explicit modeled-request rebuild.
S20-310 adds four restricted typed queries over that opaque fresh snapshot:
modeled-kind lookup, direct dependencies, direct dependents, and reverse impact
closure. Every answer is exact or fails without a partial payload.

The crate is not validation, repository, root, cache, policy, or mutation
authority. The snapshot is disposable conformance evidence, not a useful cache
or root-provenance proof. Every index rebuilds from a complete closed entity
request. The six SSMC1 entity bodies not yet represented by `sley-ssmc` and
strict root/object extraction remain explicit full-GA blockers.
The nineteen master-goal root-backed query classes, truncation, continuation,
capsules, diagnostics, and mutation affordances are not implemented.
S20-320 adds only a `RestrictedCompleteQueryCapsuleV1` evidence envelope for
successful complete restricted responses. Its dictionary and direct-edge table
add no facts, and it is always complete, nontruncated, and noncontinuable. It is
deliberately not the master context capsule.
