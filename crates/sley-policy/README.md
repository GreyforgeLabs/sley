# sley-policy

`sley-policy` implements the S20-370 protected policy-root contract, the
S20-380 narrow local capability-token profile, and the pure ordered S20-360
candidate validator plus canonical result importer/shape codec.

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

The public `validate_candidate_bytes` entry point consumes exact candidate
bytes and a closed trusted context, then runs the fourteen owning judgments in
order without mutating accepted state or a capability ledger. The current
restricted success profile is deliberately operation-free. An SSMC1 Operation
fails closed at supported resource analysis until complete operation semantics
are integrated; absent TypeDef/Function fingerprint claims are likewise a
restricted-epoch allowance rather than GA completeness.

This crate does not apply mutations, construct candidates, move refs, write
repositories, read host state, authenticate policy transitions, publish state,
execute VM adapter opcodes, confine live host resources, or deploy anything.
The current token profile uses explicit host time inputs only and remains local
to S20-380 reference-adapter enforcement.
