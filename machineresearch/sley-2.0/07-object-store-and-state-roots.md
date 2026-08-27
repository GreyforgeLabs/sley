# Object Store and State Roots

Status: S20-150 immutable object store complete; state roots not implemented.

StateRoot inputs are explicitly bounded in `REPOSITORY_MODEL_V1.md` and exclude
refs, ancestry, timestamps, paths, locks, caches, and Git. S20-160 through
S20-180 will provide state-root, pack, and GC evidence.

S20-110 evidence:

- `sley-id` is the first semantic crate;
- BLAKE3 is pinned to 1.8.2;
- 19 closed domains and 21 typed 32-byte identifiers/nonces;
- fixed vectors cover all domains plus WorkspaceId and EntityId;
- 7 unit tests plus rustdoc tests pass;
- format, workspace check, and clippy with warnings denied pass;
- Ariadne reviewed the identifier contract: PASS;
- Vulcan reviewed implementation/API/dependencies: PASS;
- no public arbitrary-domain hash function, unsafe code, filesystem, network,
  environment, SCB1, repository, policy, or VM authority.

The dependency tree includes BLAKE3's `cc` build dependency. It is locked and
was reviewed as a non-blocking S20-110 residual; supply-chain package S20-710
will disposition build-script and provenance risk globally.

S20-150 evidence:

- `OBJECT_STORE_V1.md` freezes exact SCB1 record bytes, ObjectId-only fan-out
  paths, error precedence, exclusive startup recovery, and required faults;
- `sley-store` independently checks the digest trailer and declared/path ID
  while preserving exact canonical-verifier `SCB_*` failures;
- writes use exclusive staging, file sync, reread/verify, atomic same-filesystem
  hard-link promotion without overwrite, fan-out parent fsync, final verify,
  and same-object idempotence;
- concurrent stage collisions retry; an eight-writer same-object test proves
  one `Promoted` and seven `Present` outcomes without `STORE_IO`;
- bounded reads reject oversized, symlink, and non-regular object paths;
- recovery recognizes only exact lowercase store-owned stage names in matching
  canonical fan-out directories, is explicitly exclusive-startup-only, sorts
  events, and preserves final objects;
- 21 Rust unit/fault tests plus rustdoc tests pass, including assertion-effective
  seeds for T03 digest corruption, T04 substitution, and T37 staged recovery;
- Ariadne contract review: PASS;
- Vulcan first implementation review: FAIL with two P1 findings;
- both P1s were corrected, and Vulcan re-review: PASS with no P0/P1 findings.

S20-150 does not create refs, transactions, reachability, GC, packs, state
roots, or a cross-process repository lock. A crash after promotion may leave an
unreachable immutable object but cannot advance accepted state.
