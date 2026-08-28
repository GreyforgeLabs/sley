# S20-390 Restricted Atomic Commit Closeout

Status: **restricted S20-390 atomic commit complete; the Sley 2 goal remains incomplete**

Date: 2026-08-28

Validation tier: **Tier 2 subsystem handoff**

## Closed claim

This package closes one restricted, local transaction boundary for executable
programs containing no semantic operation entities and for an empty
selected-test set. Candidate mutation operations remain supported inside that
explicit subset.

The implementation now provides:

- a non-cyclic canonical parent-bound transaction core with a derived
  `TransactionId`;
- a separate complete receipt envelope with a derived `ReceiptId`;
- a private validator-owned `ValidatedCandidatePlan` that imported result
  bytes cannot construct;
- fresh commit-time accepted-head, state-root, policy, object, tombstone,
  principal, capability-summary, candidate, expiry, and preimage rechecks;
- durable immutable-object and complete-receipt installation before accepted
  visibility;
- reverification and file/directory resync for exact existing object and
  receipt bytes before a retry may advance the head;
- one fixed checksummed `accepted` head with exclusive locking and exact
  compare-and-swap;
- explicit trusted genesis through the same receipt-before-head order;
- fail-closed recovery of owned stage remnants and verification of the current
  accepted closure plus its direct parent binding;
- exact changed-binding, tombstone, object-ID, and authenticated stored-length
  verification;
- deterministic genesis and ordinary transaction/receipt fixtures with an
  independent Python oracle;
- a persistent importer fuzz target and a fault-injection matrix.

No caller-supplied candidate result, root digest, receipt, object bytes, or
head value is commit authority. Invalid and stale candidates cannot change the
accepted head.

## Durable ordering and faults

The implemented success order is:

1. acquire exclusive accepted-head ownership;
2. load and verify the live accepted closure;
3. compare the expected parent and run fresh validation;
4. derive changed bindings, manifest, and tombstones;
5. verify, promote, and sync missing immutable objects;
6. build, write, verify, and sync the complete receipt;
7. atomically replace and sync the fixed accepted head;
8. return the new root, transaction, receipt, and candidate-result identities.

Five injected interruption boundaries cover after objects, during receipt
write, after receipt, before head rename, and after head rename before
directory sync. Every case resolves to the old complete head or the new
complete head. A sixth adversarial path forges a digest-valid receipt with the
right object ID and wrong stored length; accepted-head loading rejects it as
`TXN_OBJECT_INVENTORY_MISMATCH`.

## Independent evidence

The frozen corpus contains two accepted vectors, trusted genesis and ordinary
candidate commit, plus nine rejected cases. Eight corrupt the transaction or
receipt magic, digest, length, or trailing-byte boundary. The ninth presents a
digest-valid receipt whose authenticated object length disagrees with the
durable object inventory.

The independent Python implementation rederives both identifier domains,
strictly decodes the nineteen-field transaction and nine-field receipt,
checks nested candidate/result/root/policy bindings, and cross-checks manifest
lengths against the fixture-owned durable inventory. It imports no Rust code
and invokes no Rust process.

The production libFuzzer target drives both transaction and receipt importers,
rederives identifiers, repeats successful imports, and checks nested shape and
binding invariants. The fixture-seeded smoke completed 512 runs with no crash,
hang, or invariant failure.

## Specialist review

Nabu reviewed the dependency boundary before implementation. The accepted
design keeps `sley-txn` independent of `sley-repo`, gives S20-390 one fixed
visibility primitive, and leaves named refs and branches to S20-500.

Ariadne reviewed transaction/receipt identity, fresh authority, dependency
direction, claim wording, and accepted closure. Ariadne found one P1: receipt
manifest lengths were authenticated but not compared with durable object byte
lengths. The repository now performs that comparison; a native adversarial
test and independent rejected fixture close the finding. Ariadne also required
the phrase executable-program-operation-free so candidate mutation operations
are not misrepresented. The targeted re-review closed both findings and found
no new P0-P4 issue. The final status wording was then updated in the ADR,
specification, and repository README.

Vulcan independently found the same manifest-length P1 and missing negative
coverage. After the fix, Vulcan ran the targeted native test, fixture drift
check, independent oracle, and persistent-fuzz structural checker. The final
verdict closed both findings with no new report-grade P0-P4 issue in the
restricted S20-390 scope.

## Validation record

Focused checks:

```text
cargo test -p sley-txn --locked
cargo clippy -p sley-txn --all-targets --locked -- -D warnings
python3 scripts/generate_transaction_receipt_fixtures.py --check
uv run --project oracle/scb1 --frozen sley2-scb1-oracle check-transaction-receipt ...
uv run --project oracle/scb1 --frozen python -m unittest oracle/scb1/tests/test_codec.py -v
make transaction-receipt-persistent-fuzz-smoke
```

Tier 1 and Tier 2 closeout commands are recorded in
`evidence/validation/s20-390-atomic-commit-closeout-v1.json`: `make quick`,
`make core`, `make conformance`, and `make adversarial` all passed. The full
`make v1`, `make v2`, and release gates were not used as debugging tools.
`make v2` and `make release-check` remain intentionally fail-closed because
the full goal and release are not implemented.

## Explicitly open

This closeout does not complete:

- semantic operation-entity analysis or executable selected-test evidence;
- authenticated policy or schema transitions;
- S20-500 named refs, branches, ancestry APIs, or branch CAS;
- S20-510 comparison or S20-520 merge/conflict semantics;
- S20-530 recursive ancestry recovery and the full cross-ref crash matrix;
- clone-equivalent transaction exchange;
- protocol, bridge, CLI, live runtime, benchmark trials, supply-chain release
  evidence, packaging, publication, or GA.

S20-500 is the next dependency-complete local package. The local-write gate
remained in force: no runtime deployment, provider call, publication, spend,
trading action, push, or external system mutation occurred.
