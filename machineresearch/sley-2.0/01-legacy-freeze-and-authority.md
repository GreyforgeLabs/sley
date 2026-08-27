# Legacy Freeze and Authority

Observation time: 2026-08-27 EDT

## Frozen evidence

- Commit: `397fa28ded15ddbeca5404ee00a3f5bd5546b296`
- Frozen worktree branch: `codex/sley-ai-foundation-20260822`
- Frozen worktree state: clean; local branch observed 53 commits ahead of
  `origin/public`
- Remote: `https://github.com/GreyforgeLabs/sley.git`
- Artifact: `<LOCAL_HOME>/archive/sley/1.2.0/sley-1.2.0-linux-x86_64.tar.gz`
- SHA-256: `b24f19c6a348751c93c9cf63f6f4154f6132796112c26f9d8c0e71324080dbc7`
- Size: `4,611,024` bytes
- Exact source snapshot: `<LOCAL_HOME>/archive/sley/1.2.0/sley-1.2.0-source-397fa28.tar.gz`
- Source SHA-256: `1c866d360305d0b511dc2c33c4907b33544fc73bc6cb6fa4c0e1687df48eb90e`

The snapshot contains the frozen revision’s 99 JSON schemas, 187 contract
fixtures, 12 accepted and 66 rejected top-level corpus cases, 264 integration
checks reported by `docs/v1.2/STATUS.md`, claim-verification material,
benchmarks, audits, and negative bootstrap/training evidence. The artifact
manifest contains 1,067 payload files and records local-candidate-only,
unsigned, publication/tag/upload unauthorized state.

## Live legacy checkout observation

The primary `<LOCAL_HOME>/sley` checkout was on `public` at
`7b6fb16b32d256442c44538ee35d761b244228cc`, ahead 3 and behind 3 relative to
`origin/public`, with user/session changes in `README.md`,
`docs/SleyClaimEvidence.md`, and `llms.txt`. Sley 2 did not modify it.

Observed worktrees included the frozen commit worktree, a public-closeout
worktree, a `release/sley-v1.2.0-public-20260826` worktree, the primary public
checkout, and two research branches. These are navigation facts, not Sley 2
dependencies.

## Public state observation

GitHub reported `GreyforgeLabs/sley` public with default branch `public` and
v1.1 as latest published release at observation time. No v1.2.0 public release
was observed. This is time-sensitive and may be changed by the separately owned
1.2 deployment session.

## Superseded plans

The authoritative master goal cancels Sley 1.2.1, 1.2.2, 1.2.3, and 1.2.4 as
implementation arcs. Their files/history remain preserved as design evidence.
This repository will not edit those plans or use them as prerequisites.
