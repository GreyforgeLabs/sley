# Architecture Decision Records

ADRs are append-only decisions. Superseding an ADR requires a new ADR that
names the old one; history is not rewritten. A legacy Sley pattern cannot enter
the kernel without a specific disposition ADR.

Current records:

- ADR-0001: machine-native lineage and no canonical text
- ADR-0002: clean-room legacy boundary
- ADR-0003: crate authority and dependency direction
- ADR-0004: canonical identities and domain separation
- ADR-0005: protected policy and judged-candidate isolation
- ADR-0006: M0 validation and fail-closed incomplete gates
- ADR-0007: dedicated SSMC canonical value-hash domain
- ADR-0008: dedicated derived VM bytecode cache-key domain
