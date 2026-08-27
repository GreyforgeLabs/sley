# Sley 2 — Machine Genesis

Sley 2 is a new, incompatible programming-system lineage in which programs are
created, stored, changed, executed, tested, versioned, and exchanged as typed
semantic state. Its canonical program form is SSMC1, its canonical encoding is
SCB1, and its machine interface is SMP1.

The governing doctrine is: **machines do not write source; they mutate verified
program state**. This repository therefore contains no Sley source parser,
canonical text format, formatter, conventional LSP, or compatibility promise
for Sley 1.x.

## Current phase

Phase M0 is complete. M1 packages S20-100 through S20-170 now provide SCB1,
typed identifiers, an independent oracle, schema epochs, the immutable object
store, deterministic state roots, and uncompressed root/object repository
packs. S20-180 and the scoped M1 core/adversarial/fuzz-smoke profiles now pass.
M2 is next; no SSMC execution kernel or runtime exists yet. Every next package
must follow `docs/WORK_PACKAGES.md`.

## Authority

- Product goal: `<LOCAL_HOME>/machineresearch/Sley2.0mastergoal.md`
- Local architecture: `ARCHITECTURE.md`
- Security and threat register: `SECURITY.md`
- Normative drafts: `docs/spec/`
- Work-package DAG: `docs/WORK_PACKAGES.md`
- Evidence dossier: `machineresearch/sley-2.0/`

The product goal controls when this repository disagrees with a local draft.

## Authority boundaries

This repository is local-only. No push, tag, upload, deployment, publication,
provider spend, or public claim is authorized. Sley 1.2 deployment and release
work belongs to a separate session and repository worktree.

## Validation

`make quick` and `make check-changed` validate the implemented M0/M1 surface.
Later profiles are present but intentionally fail closed until their
corresponding work packages land. `make v2` remains the eventual authoritative
full gate.
