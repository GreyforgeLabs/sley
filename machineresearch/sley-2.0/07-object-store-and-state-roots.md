# Object Store and State Roots

Status: S20-160 deterministic state roots complete.

StateRoot inputs are explicitly bounded in `REPOSITORY_MODEL_V1.md` and exclude
refs, ancestry, timestamps, paths, locks, caches, and Git. S20-170 and S20-180
will provide pack and GC evidence.

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

S20-160 evidence:

- `STATE_ROOT_V1.md` freezes contract tag 160, nine required fields, exact
  ordering, registry authorization, interpretation flags, exclusions, and
  strict import behavior;
- `sley-state-root` exposes no public unregistered derivation route: accepted
  construction/import requires the exact nonzero conformance epoch row,
  descriptor, and preserved decoder;
- the zero-epoch byte fixture remains synthetic and is rejected with
  `SCHEMA_EPOCH_MISMATCH` at the authorization boundary;
- the independent Python reconstruction agrees on raw descriptor digests,
  182-byte epoch record, epoch ID `a7fcf97a85d41ef9b1c89394a324f2dc7ec875b9ded48a783104314857dc870e`,
  415-byte payload, 460-byte preimage, 492-byte stored record, and StateRoot
  `d3914cbffcde449959d6a35eddb16293c3424f4980e64e687a4f47358ad2770a`;
- unordered builder inputs derive identical roots, while strict import rejects
  field/map/set disorder, duplicates, missing/unknown fields, nonminimal
  varints, epoch mismatch, digest mismatch, trailing bytes, and limits;
- 12 Rust tests, the independent vector gate, format, and strict Clippy pass;
- Ariadne's initial zero-epoch authorization ambiguity was corrected before
  implementation acceptance;
- Vulcan review: PASS with no P0/P1 report-grade finding.

The conformance epoch is not the complete production schema epoch. S20-200
must add the full SSMC contract set, and S20-170/S20-390 still own pack and
transaction/ancestry evidence.
