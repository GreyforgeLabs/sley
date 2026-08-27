# Repository Pack v1

Status: S20-170 normative contract.

## Scope

Repository Pack v1 is the host-independent, root/object-only exchange profile
needed to reconstruct exact standalone `StateRoot` bytes in a clean Sley 2
object store. It contains no filesystem paths, Git facts, refs, transactions,
receipts, signatures, compressed blocks, leases, pins, or runtime metadata.

S20-170 owns canonical pack bytes, strict preflight verification, immutable
object promotion, and exact root reconstruction. S20-540 later owns a new
profile or contract for transactions, refs, branch heads, ancestry, and
clone-equivalent repository reconstruction. ZJX may transport an exact pack
later, but never changes this contract's bytes or semantics.

## Envelope and identity

The standalone contract uses:

```text
format_version    = 1
contract_tag      = 170
contract_domain   = "sley2.repository-pack.v1"
digest_domain_tag = 18
kind_tag          = 170
```

The envelope is:

```text
pack_preimage = "SLEYSCB1" || uvar(1) || uvar(170) ||
                PackSchemaEpochId[32] || len(payload) || payload
RepositoryPackId = BLAKE3-256("sley2.repository-pack.v1" || pack_preimage)
stored_pack = pack_preimage || RepositoryPackId[32]
```

The digest trailer is outside its own preimage. The envelope epoch selects an
immutable registry row containing the exact tag-170 descriptor and preserved
decoder. Contained schema epochs describe contained roots and objects; they do
not select the pack decoder.

The conformance descriptor freezes raw BLAKE3-256 hashes of these exact ASCII
texts:

```text
field schema preimage = sley2.repository-pack.v1.schema:required(1:pack_version u32,2:schema_epochs set epoch_entry,3:roots set root_entry,4:refs empty_set,5:object_inventory set object_entry,6:transaction_inventory empty_set,7:compression_profile u32,8:digest_tree digest_tree,9:signature_metadata option_bytes);epoch_entry=record(1:schema_epoch_id fixed32,2:bootstrap_preimage bytes);root_entry=record(1:state_root fixed32,2:stored_bytes bytes);object_entry=record(1:object_id fixed32,2:byte_length u64,3:stored_bytes bytes);digest_tree=record(1:algorithm_tag u32,2:leaf_count u64,3:leaves list fixed32,4:root_digest fixed32);profile=0;signature=none;epoch=1
field_schema_hash = 7231a31c5d9cc159ce9d161ecc434c4b98613f97a00e07fd0728c45128f94e21

decoder limits preimage = sley2.repository-pack.v1.decoder-limits:stored=67108864,expanded=67108864,epochs=256,roots=4096,objects=65536,leaves=69888,allocation=134217728,compression=none
decoder_limits_hash = 38a807922870bae9aca1bbd0afb8d87f2511c876bc087ce1616cbb7c7cc95e00
```

Their exact digests are frozen in the implementation and conformance fixture.

## Payload

The payload is a closed SCB1 Record with all fields required:

| Tag | Field | S20-170 type and rule |
|---:|---|---|
| 1 | `pack_version` | `UInt<32>`; exactly `1` |
| 2 | `schema_epochs` | canonical set of epoch entries, sorted by `SchemaEpochId` |
| 3 | `roots` | nonempty canonical set of root entries, sorted by `StateRoot` |
| 4 | `refs` | canonical set; MUST be empty |
| 5 | `object_inventory` | canonical set of object entries, sorted by `ObjectId` |
| 6 | `transaction_inventory` | canonical set; MUST be empty |
| 7 | `compression_profile` | `UInt<32>`; exactly `0` (`none`) |
| 8 | `digest_tree` | digest-tree record below |
| 9 | `signature_metadata` | option bytes; MUST be absent |

An epoch entry carries its declared `SchemaEpochId` and exact canonical
`SLEYEP01` bootstrap preimage. A root entry carries its declared `StateRoot`
and exact standalone tag-160 bytes. An object entry carries its declared
`ObjectId`, exact byte length, and exact standalone object bytes. Duplicate or
noncanonical identifiers fail; a decoder never sorts input.

The epoch inventory MUST contain exactly the pack schema epoch and every epoch
selected by a contained root. Every bootstrap preimage MUST derive its declared
ID. Every root MUST import through the exact contained epoch and derive its
declared ID. The root set MUST be dependency-closed. For the S20-160 root
shape, the object inventory MUST equal the union of every entity binding,
contract root, and test root referenced by the root set. Missing and surplus
objects both fail closed.

## Digest tree

The tree algorithm tag is `1`, BLAKE3-256. One leaf exists for every epoch,
root, and object entry, in this exact order: all epochs by ID, all roots by ID,
then all objects by ID. Section tags are `1`, `2`, and `3` respectively.

```text
leaf_preimage = "sley2.repository-pack-leaf.v1" ||
                uvar(section_tag) || identifier[32] ||
                uvar(len(stored_bytes)) || stored_bytes
leaf = BLAKE3-256(leaf_preimage)

node = BLAKE3-256("sley2.repository-pack-node.v1" || left[32] || right[32])
```

The payload stores the exact ordered leaf list, its count, and the tree root.
At each level adjacent leaves are paired; an unpaired final digest is promoted
unchanged. The tree MUST be nonempty. Any leaf-list or root disagreement is
`PACK_DIGEST_TREE_MISMATCH`. The outer `RepositoryPackId` additionally binds
the header, closed empty sections, compression profile, tree, and signature
absence.

## Resource limits

All SCB1 epoch-1 canonical limits still apply. This contract adds closed pack
limits:

- stored pack bytes: `67,108,864`;
- expanded bytes across embedded epoch, root, and object records: `67,108,864`;
- schema epochs: `256`;
- roots: `4,096`;
- objects: `65,536`;
- digest leaves: `69,888` (the exact sum of the three count ceilings);
- decoder allocation budget: `134,217,728` bytes.

Profile `0` performs no decompression. Any other profile returns
`PACK_COMPRESSION_UNSUPPORTED` before interpreting blocks. A future compressed
profile MUST stream against the expanded-byte ceiling and return
`PACK_DECOMPRESSION_LIMIT` before allocation or object promotion.

## Import phases and durability

Import is split into preflight and persistence:

1. bound stored bytes, decode the closed envelope/payload, and verify the pack
   trailer;
2. verify canonical order, counts, closed profiles, every content ID, and the
   complete digest tree;
3. import every epoch and root through its exact preserved decoder;
4. prove dependency closure and exact object-inventory closure;
5. run the selected canonical verifier over every object without store writes;
6. only after all preflight checks pass, promote immutable objects through the
   object store;
7. return reconstructed accepted roots only after all promotions succeed.

S20-170 writes no ref and accepts no repository head. An I/O interruption
during Step 6 may leave unreachable immutable objects, matching the object
store/transaction durability model, but it cannot expose a successful import
or advance accepted state. Re-import is idempotent.

## Stable failures

- exact malformed SCB1 failures preserve `SCB_*` where applicable;
- `PACK_VERSION_UNSUPPORTED` rejects a non-v1 payload;
- `PACK_DIGEST_MISMATCH` rejects the outer pack ID;
- `PACK_DIGEST_TREE_MISMATCH` rejects leaf or tree disagreement;
- `PACK_CANONICAL_ORDER` and `PACK_DUPLICATE_ENTRY` reject inventory order;
- `PACK_SCHEMA_UNSUPPORTED` rejects absent, surplus, or unsupported epochs;
- `PACK_ROOT_INVALID` rejects root identity, decoding, or dependency closure;
- `PACK_OBJECT_MISSING` and `PACK_OBJECT_UNEXPECTED` reject inventory closure;
- `PACK_OBJECT_CORRUPT` rejects object identity or canonical verification;
- `PACK_RESOURCE_LIMIT` rejects any pack-level bound;
- `PACK_COMPRESSION_UNSUPPORTED` rejects nonzero profiles now;
- `PACK_DECOMPRESSION_LIMIT` is reserved for a future compressed profile;
- `PACK_PROFILE_UNSUPPORTED` rejects nonempty refs/transactions or signatures;
- store persistence preserves exact `STORE_*` failures.

There is no text/path/Git field, so T50 facts cannot enter canonical bytes.
T41 is covered by closed decoding, full preflight, closure checks, and importer
corruption tests. T42 fails closed because compression is unavailable. T51 is
covered at the Sley pack boundary: any transport alteration changes a content
digest, tree root, or outer pack ID before persistence.

## S20-170 acceptance

- a fixed conformance pack round-trips byte-for-byte and has an independently
  reproduced `RepositoryPackId` and tree root;
- export order does not affect bytes or identity;
- import into a clean store reconstructs the exact standalone root bytes and
  all referenced objects;
- missing, surplus, duplicated, reordered, substituted, or corrupted content
  fails before object promotion;
- wrong version/profile, nonempty refs/transactions, signature presence,
  trailing bytes, and resource-limit breaches fail closed;
- changing repository path, Git metadata, host identity, timestamps, or source
  checkout has no API or byte path into pack identity;
- re-import is idempotent;
- S20-540 features remain rejected and unclaimed.
