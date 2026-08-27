# ADR-0015: Protected policy roots are separate canonical authority data

Status: accepted for S20-370

## Decision

Represent machine policy as a registry-authorized, separately
content-addressed `PolicyRoot` whose immutable record binds workspace,
principal-specific grant data, protected entities, required tests/contracts,
expiry data, parent lineage, and an external-higher-authority-only transition
mode.

Expose only immutable lookup, mandatory-plan finalization, and pure
ordinary-program isolation. Do not expose policy-transition authorization,
capability tokens, runtime scope enforcement, candidate construction, or
commit.

## Rationale

Embedding policy into ordinary program entities would let a candidate weaken
the rules that judge it. A separate digest already bound by `StateRoot` permits
exact comparison without giving program mutations a policy-root operation.
Principal-specific grants prevent global allowlists from silently granting the
same policy data to every identity.

## Consequences

- `PrincipalId` is opaque fixed data and grants nothing by itself;
- accepted policy wrappers and grants are immutable outside the crate;
- mandatory test/contract selection becomes policy-final evidence bound to one
  exact root, while full candidate validation remains later;
- all policy transitions remain unapproved until a separate authenticated
  higher-authority contract exists;
- S20-380 owns tokens, authenticators, replay, live scope, expiry, and budgets;
- final production-epoch assembly remains a release blocker.
