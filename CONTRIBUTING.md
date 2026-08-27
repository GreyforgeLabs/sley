# Contributing to Sley 2

Sley 2 is currently a local, pre-publication project. Contribution does not
grant push, merge, deploy, tag, release, publication, provider-spend, or public
claim authority.

## Slice contract

Each change must name one unblocked work package, inspect its governing spec and
invariants, classify reused ideas as copied/adapted/reimplemented/new, and add
contracts, positive and negative tests, property or fuzz coverage where the
boundary warrants it, documentation, and evidence in the same slice.

Importing a Sley 1.x implementation pattern requires a prior ADR and disposition
entry. Legacy code may be executed as an external oracle; it may not be copied
into the new kernel.

## Validation economy

Run the smallest meaningful check first. `make quick` is the M0 inner loop;
`make check-changed` reports affected surfaces. Use subsystem gates at work-
package boundaries. `make v2` is the authoritative full product gate and must
not be used as a debugging strategy.

Record command, environment, commit, seed, duration, result, cache use, and
skips in the dossier. Never weaken checks to make a demonstration pass.

## Commit discipline

Use one coherent purpose and a conventional commit message. Commit local work
before a phase boundary or handoff. Do not add `Co-Authored-By`. Do not amend,
rebase, force-push, or absorb unrelated changes without explicit direction.

## Prohibited additions

Do not add Sley source syntax, parser, canonical text, formatter, Tree-sitter,
conventional LSP, REPL, human projection, source compatibility, unrestricted
shell, mandatory Greyforge dependency, native backend, marketplace, or self-
hosting work to the 2.0 GA path.
