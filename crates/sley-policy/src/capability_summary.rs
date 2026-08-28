//! Canonical proposal-only capability-summary projection.
//!
//! This module projects already constructed capability-token bodies into the
//! exact S20-345 summary preimage. It checks outer identity bindings and
//! duplicate token digests, but it does not authenticate a token, inspect a
//! ledger, authorize a candidate, or consume capability budget. S20-360 must
//! verify every projected token against explicit trusted key material before
//! treating the resulting digest as an authenticated context fact.

use std::collections::BTreeSet;

use sley_id::{
    CapabilitySummaryDigest, CapabilityTokenDigest, PolicyRootId, PrincipalId, StateRoot,
    WorkspaceId,
};
use sley_scb1::{
    MAX_STANDALONE_BYTES, ScbError, ScbErrorCode, encode_list, encode_record, encode_uvar,
};

use crate::{CapabilityError, CapabilityErrorCode, CapabilityResourceBudget, CapabilityToken};

const SUMMARY_MAGIC: &[u8; 8] = b"SLEYCAS1";
const SUMMARY_VERSION: u64 = 1;
const SUMMARY_FORMAT_VERSION: u32 = 1;

/// Canonical proposal-only capability summary and its exact digest preimage.
///
/// This value proves only deterministic projection. It is not evidence that
/// any token authenticator, issuer, key, expiry, scope, budget, replay state,
/// or policy judgment was checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilitySummaryProjection {
    digest: CapabilitySummaryDigest,
    preimage: Vec<u8>,
    token_digests: Vec<CapabilityTokenDigest>,
}

impl CapabilitySummaryProjection {
    /// Returns the exact proposal-binding digest.
    #[must_use]
    pub const fn digest(&self) -> CapabilitySummaryDigest {
        self.digest
    }

    /// Returns the exact `SLEYCAS1` digest preimage.
    #[must_use]
    pub fn preimage(&self) -> &[u8] {
        &self.preimage
    }

    /// Returns projected token digests in canonical grant-summary byte order.
    #[must_use]
    pub fn token_digests(&self) -> &[CapabilityTokenDigest] {
        &self.token_digests
    }
}

/// Builds the canonical S20-345 proposal-only capability summary.
///
/// Grant summaries are sorted by their complete canonical bytes, not caller
/// order. Duplicate token digests and any token whose principal, workspace,
/// protected policy, or accepted state root differs from the outer summary
/// fail closed. Empty summaries are canonical.
///
/// This function deliberately does not verify token MACs or authority. The
/// S20-360 validator owns that later judgment with explicit trusted keys.
///
/// # Errors
///
/// Returns a preserved capability binding/canonicality error or an exact SCB1
/// resource failure.
pub fn build_capability_summary_projection(
    principal_id: PrincipalId,
    workspace_id: WorkspaceId,
    policy_root_id: PolicyRootId,
    state_root: StateRoot,
    tokens: &[CapabilityToken],
) -> Result<CapabilitySummaryProjection, CapabilityError> {
    let mut seen = BTreeSet::new();
    let mut grants = Vec::with_capacity(tokens.len());
    for token in tokens {
        let body = token.body();
        if body.principal_id != principal_id {
            return capability_failure(CapabilityErrorCode::PrincipalMismatch);
        }
        if body.workspace_id != workspace_id {
            return capability_failure(CapabilityErrorCode::WorkspaceMismatch);
        }
        if body.policy_root != policy_root_id {
            return capability_failure(CapabilityErrorCode::PolicyRootMismatch);
        }
        if body.state_root != state_root {
            return capability_failure(CapabilityErrorCode::StateRootMismatch);
        }
        if !seen.insert(token.digest()) {
            return capability_failure(CapabilityErrorCode::CanonicalInvalid);
        }
        grants.push((encode_grant(token)?, token.digest()));
    }
    grants.sort_by(|left, right| left.0.cmp(&right.0));

    let summary_record = encode_record(&[
        (1, encode_uvar(u64::from(SUMMARY_FORMAT_VERSION))),
        (2, principal_id.as_bytes().to_vec()),
        (3, workspace_id.as_bytes().to_vec()),
        (4, policy_root_id.as_bytes().to_vec()),
        (5, state_root.as_bytes().to_vec()),
        (
            6,
            encode_list(
                &grants
                    .iter()
                    .map(|(encoded, _)| encoded.clone())
                    .collect::<Vec<_>>(),
            )?,
        ),
    ])?;
    let mut preimage = Vec::with_capacity(SUMMARY_MAGIC.len() + 20 + summary_record.len());
    preimage.extend_from_slice(SUMMARY_MAGIC);
    preimage.extend_from_slice(&encode_uvar(SUMMARY_VERSION));
    preimage.extend_from_slice(&encode_uvar(
        u64::try_from(summary_record.len())
            .map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?,
    ));
    preimage.extend_from_slice(&summary_record);
    if preimage.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit).into());
    }
    Ok(CapabilitySummaryProjection {
        digest: CapabilitySummaryDigest::derive(&preimage),
        preimage,
        token_digests: grants.into_iter().map(|(_, digest)| digest).collect(),
    })
}

fn encode_grant(token: &CapabilityToken) -> Result<Vec<u8>, ScbError> {
    let body = token.body();
    encode_record(&[
        (1, token.digest().as_bytes().to_vec()),
        (2, body.issuer_id.as_bytes().to_vec()),
        (3, body.key_id.as_bytes().to_vec()),
        (4, body.effect_id.as_bytes().to_vec()),
        (5, encode_uvar(u64::from(body.effect_kind_tag))),
        (6, body.scope_hash.as_bytes().to_vec()),
        (7, body.adapter_id.as_bytes().to_vec()),
        (8, encode_budget(body.budget)?),
        (9, encode_uvar(body.issued_unix_millis)),
        (10, encode_uvar(body.expiry_unix_millis)),
        (11, body.token_nonce.as_bytes().to_vec()),
    ])
}

fn encode_budget(budget: CapabilityResourceBudget) -> Result<Vec<u8>, ScbError> {
    encode_record(&[
        (1, encode_uvar(budget.max_fuel)),
        (2, encode_uvar(budget.max_memory_bytes)),
        (3, encode_uvar(budget.max_output_bytes)),
        (4, encode_uvar(budget.max_effect_count)),
        (5, encode_uvar(budget.max_mutation_count)),
        (6, encode_uvar(budget.max_adapter_calls)),
    ])
}

fn capability_failure<T>(code: CapabilityErrorCode) -> Result<T, CapabilityError> {
    Err(CapabilityError::Capability(code))
}

#[cfg(test)]
mod tests {
    use sley_id::{CandidateNonce, EntityId, GenesisNonce, ReferenceAdapterId, ValueHash};
    use sley_ssmc::EffectKind;

    use super::*;
    use crate::{
        CapabilityIssuerId, CapabilityKeyId, CapabilitySecret, CapabilityTokenNonce,
        CapabilityTokenRequest, CapabilityTrustedKey, PolicyResourceCeilings, PolicyRootBuilder,
        PrincipalGrantBuilder, conformance_registry, issue_capability_token,
    };

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn fixture() -> (
        PrincipalId,
        WorkspaceId,
        crate::AcceptedPolicyRoot,
        CapabilityTrustedKey,
        StateRoot,
    ) {
        let principal = PrincipalId::from_bytes(id(1));
        let workspace = WorkspaceId::derive(GenesisNonce::from_bytes(id(2)));
        let adapter = ReferenceAdapterId::derive_kind(1);
        let grant = PrincipalGrantBuilder::new(PolicyResourceCeilings::new(9, 9, 9, 9, 9, 9))
            .effect_kind(EffectKind::StdoutWrite)
            .adapter_id(adapter)
            .build()
            .unwrap();
        let policy = PolicyRootBuilder::new(workspace)
            .principal_grant(principal, grant)
            .build(&conformance_registry().unwrap())
            .unwrap();
        let key = CapabilityTrustedKey::new(
            CapabilityIssuerId::from_bytes(id(3)),
            CapabilityKeyId::from_bytes(id(4)),
            CapabilitySecret::from_bytes(id(5)),
        );
        (
            principal,
            workspace,
            policy,
            key,
            StateRoot::from_bytes(id(6)),
        )
    }

    fn token(
        principal: PrincipalId,
        workspace: WorkspaceId,
        policy: &crate::AcceptedPolicyRoot,
        key: &CapabilityTrustedKey,
        state_root: StateRoot,
        nonce: u8,
    ) -> CapabilityToken {
        issue_capability_token(
            policy,
            key,
            &CapabilityTokenRequest {
                principal_id: principal,
                workspace_id: workspace,
                state_root,
                effect_id: EntityId::derive(
                    workspace,
                    CandidateNonce::from_bytes(id(7)),
                    11,
                    u64::from(nonce),
                ),
                effect_kind: EffectKind::StdoutWrite,
                scope_hash: ValueHash::from_bytes(id(nonce)),
                adapter_id: ReferenceAdapterId::derive_kind(1),
                budget: CapabilityResourceBudget::new(1, 1, 1, 1, 1, 1),
                now_unix_millis: 10,
                expiry_unix_millis: 20,
                token_nonce: CapabilityTokenNonce::from_bytes(id(nonce)),
            },
        )
        .unwrap()
    }

    #[test]
    fn empty_summary_is_canonical_and_deterministic() {
        let (principal, workspace, policy, _, state_root) = fixture();
        let left = build_capability_summary_projection(
            principal,
            workspace,
            policy.root(),
            state_root,
            &[],
        )
        .unwrap();
        let right = build_capability_summary_projection(
            principal,
            workspace,
            policy.root(),
            state_root,
            &[],
        )
        .unwrap();
        assert_eq!(left, right);
        assert_eq!(left.preimage()[..8], *SUMMARY_MAGIC);
        assert!(left.token_digests().is_empty());
    }

    #[test]
    fn empty_summary_fixed_vector() {
        let summary = build_capability_summary_projection(
            PrincipalId::from_bytes(id(1)),
            WorkspaceId::from_bytes(id(2)),
            PolicyRootId::from_bytes(id(3)),
            StateRoot::from_bytes(id(4)),
            &[],
        )
        .unwrap();
        assert_eq!(
            summary.digest().as_bytes(),
            &[
                0x1e, 0xe3, 0x7d, 0x0d, 0x27, 0x65, 0x0d, 0x46, 0x0d, 0x7a, 0xcf, 0xfd, 0x64, 0x02,
                0xab, 0x58, 0x89, 0xb5, 0x67, 0x35, 0x12, 0xe5, 0x69, 0x30, 0x20, 0x89, 0x72, 0xf3,
                0x9c, 0x2a, 0xcf, 0x62,
            ]
        );
    }

    #[test]
    fn grant_order_is_canonical_and_duplicate_digests_fail() {
        let (principal, workspace, policy, key, state_root) = fixture();
        let first = token(principal, workspace, &policy, &key, state_root, 8);
        let second = token(principal, workspace, &policy, &key, state_root, 9);
        let forward = build_capability_summary_projection(
            principal,
            workspace,
            policy.root(),
            state_root,
            &[first.clone(), second.clone()],
        )
        .unwrap();
        let reverse = build_capability_summary_projection(
            principal,
            workspace,
            policy.root(),
            state_root,
            &[second, first.clone()],
        )
        .unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(
            build_capability_summary_projection(
                principal,
                workspace,
                policy.root(),
                state_root,
                &[first.clone(), first],
            ),
            Err(CapabilityError::Capability(
                CapabilityErrorCode::CanonicalInvalid
            ))
        );
    }

    #[test]
    fn outer_bindings_are_checked_without_claiming_authentication() {
        let (principal, workspace, policy, key, state_root) = fixture();
        let token = token(principal, workspace, &policy, &key, state_root, 8);
        assert_eq!(
            build_capability_summary_projection(
                PrincipalId::from_bytes(id(99)),
                workspace,
                policy.root(),
                state_root,
                &[token],
            ),
            Err(CapabilityError::Capability(
                CapabilityErrorCode::PrincipalMismatch
            ))
        );
    }
}
