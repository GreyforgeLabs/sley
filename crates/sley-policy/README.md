# sley-policy

`sley-policy` implements the S20-370 protected policy-root contract.

The crate constructs and strictly imports immutable `PolicyRoot` records through
an exact schema registry and preserved decoder. A policy root can name opaque
principals, exact allowed effect-kind and mutation-class tags, allowed adapter
identities, required tests/contracts, protected entity identities, resource
ceilings, expiry data, and its external-higher-authority-only transition mode.

This crate does not issue capability tokens, validate runtime capability use,
apply mutations, construct candidates, move refs, write repositories, read host
state, check wall-clock expiry, authenticate policy transitions, or publish
state. Authenticated policy transitions and live capability/token enforcement
are later packages.
