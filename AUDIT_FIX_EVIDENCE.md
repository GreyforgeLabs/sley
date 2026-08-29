# GitHub Audit Remediation Evidence

Version: `2.0.0-alpha.1`

## GF-AUD2-015

The operator explicitly selected a sanitized public GitHub source repository.
`repository-policy.json` records that disposition while keeping releases,
tags, packages, deployments, provider spend, and product claims disabled.

The public-policy checker fails on doctrine drift, non-public CI visibility,
machine-local home paths, disabled-peer identifiers, high-confidence token or
private-key forms, and common secret-bearing tracked filenames. The same
checker runs in `make quick` and GitHub Actions.
The two repository checks that previously read a machine-local master-goal path
now consume a minimal sanitized repository-local constraint projection, so a
fresh public clone can validate without private authority files.

Before public visibility is enabled, the remote history is backed up locally,
machine-local paths are rewritten from reachable history, the rewritten
history is rescanned, and the default branch is force-updated under the
operator-authorized audit closeout.
