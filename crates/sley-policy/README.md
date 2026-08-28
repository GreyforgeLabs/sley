# sley-policy

`sley-policy` implements the S20-370 protected policy-root contract, the
S20-380 narrow local capability-token profile, and the non-authoritative
canonical S20-360 candidate-result importer/shape codec.

The crate constructs and strictly imports immutable `PolicyRoot` records through
an exact schema registry and preserved decoder. A policy root can name opaque
principals, exact allowed effect-kind and mutation-class tags, allowed adapter
identities, required tests/contracts, protected entity identities, resource
ceilings, expiry data, and its external-higher-authority-only transition mode.
It also issues and verifies exact-root/scope/adapter capability tokens with a
host-supplied keyed BLAKE3 secret, and owns the deterministic caller-owned
replay/budget ledger used by runtime enforcement.
Policy-root records do not embed capability tokens or authenticators; S20-370
root serialization and S20-380 token serialization remain separate contracts.
Candidate-result import verifies exact bytes, its digest trailer, all fourteen
monotonic phase records, diagnostic bounds, set order, and candidate/root
presence rules. Import does not prove that a phase ran; only the crate-private
validator construction lane may create validator-owned results.

This crate does not apply mutations, construct candidates, move refs, write
repositories, read host state, authenticate policy transitions, publish state,
execute VM adapter opcodes, confine live host resources, or deploy anything.
The current token profile uses explicit host time inputs only and remains local
to S20-380 reference-adapter enforcement.
