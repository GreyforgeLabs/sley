# Object Store and State Roots

Status: S20-110 identifiers complete; object store/state roots not implemented.

StateRoot inputs are explicitly bounded in `REPOSITORY_MODEL_V1.md` and exclude
refs, ancestry, timestamps, paths, locks, caches, and Git. S20-150 through
S20-180 will provide implementation, corruption, pack, and GC evidence.

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
