# Object Store and State Roots

Status: S20-170 repository packs and clean reconstruction complete.

StateRoot inputs are explicitly bounded in `REPOSITORY_MODEL_V1.md` and exclude
refs, ancestry, timestamps, paths, locks, caches, and Git. S20-170 now provides
root/object pack reconstruction; S20-180 still owns reachability and GC.

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
must add the full SSMC contract set, and S20-390 still owns transaction and
ancestry evidence.

S20-170 evidence:

- `REPOSITORY_PACK_V1.md` freezes tag 170, domain tag 18, exact descriptor
  preimages/digests, typed epoch/root/object inventories, closed 64 MiB limits,
  and the five-leaf conformance Merkle algorithm;
- the only implemented profile is uncompressed and root/object-only; refs,
  transactions, signatures, and other compression profiles fail closed rather
  than claiming S20-540 clone equivalence;
- export canonicalizes epochs, roots, and objects, requires dependency closure,
  and reads every object through the canonical verifier;
- import verifies the outer pack ID, exact pack/root epochs, complete digest
  tree, root dependency closure, exact object closure, every object ID, and the
  canonical object verifier before the first immutable-store write;
- clean import reconstructs exact standalone roots and referenced objects;
  re-import reports verified objects as present and is idempotent;
- 16 Rust unit/adversarial tests cover malformed outer IDs, valid-outer-ID tree
  tampering, missing/surplus/reordered/substituted objects, unsupported future
  profiles, dependency closure, verifier rejection, and zero-write preflight
  failures;
- an independent Python decoder reproduces the 1,421-byte fixture, five leaves,
  tree root `1c0ee93f9eaf275808b7f50086ccb2f7aebd8eb61bcf2ad3896f642c34fa13d9`,
  and `RepositoryPackId`
  `7a1e139c74191a46cbf03275dcb4ae4e4625765d6d6ee412076628d49d867df8`;
- Nabu's design review passed after the pack-wide limits and leaf schema were
  frozen; Vulcan's independent implementation review passed with no
  report-grade findings.

The conformance pack reconstructs the exact S20-160 root/object surface. It is
not a pack manifest retention implementation, compressed transport, repository
head, transaction DAG, ref importer, or clone-equivalent profile. S20-180 owns
GC roots/pins/leases, and S20-540 owns later exchange equivalence.
