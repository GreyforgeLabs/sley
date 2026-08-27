# New-Lineage Repository Baseline

- Repository: `<LOCAL_HOME>/sley2`
- Branch: `main`
- History: independent `git init`; no remote configured
- M0 baseline commit: `3a0fd1b46858e31a1e040dda9d4fafe65e83ed38`
- Rust: pinned stable `1.93.0`, edition 2024, resolver 3
- Semantic crates: zero during M0
- Legacy source copied: none
- Publication/deploy/tag/upload authority: none

The root workspace is intentionally empty after M0 review and commit. Planned
crate ownership is frozen in `ARCHITECTURE.md` and
`docs/WORK_PACKAGES.md`. Product gates fail closed as `NOT_IMPLEMENTED`; only
M0 structural validation can pass.
