#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use core::fmt;

const ID_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Domain {
    Workspace,
    Entity,
    Object,
    StateRoot,
    Transaction,
    Receipt,
    SchemaEpoch,
    PolicyRoot,
    CapabilityToken,
    Candidate,
    CandidateResult,
    Query,
    ContextCapsule,
    SemanticFingerprint,
    ValueHash,
    BytecodeCacheKey,
    Observation,
    ExecutionReport,
    TestReport,
    RepositoryPack,
    ProtocolHandshake,
    ReferenceAdapter,
    AdapterState,
    AdapterTranscript,
}

impl Domain {
    #[cfg(test)]
    const ALL: [Self; 24] = [
        Self::Workspace,
        Self::Entity,
        Self::Object,
        Self::StateRoot,
        Self::Transaction,
        Self::Receipt,
        Self::SchemaEpoch,
        Self::PolicyRoot,
        Self::CapabilityToken,
        Self::Candidate,
        Self::CandidateResult,
        Self::Query,
        Self::ContextCapsule,
        Self::SemanticFingerprint,
        Self::ValueHash,
        Self::BytecodeCacheKey,
        Self::Observation,
        Self::ExecutionReport,
        Self::TestReport,
        Self::RepositoryPack,
        Self::ProtocolHandshake,
        Self::ReferenceAdapter,
        Self::AdapterState,
        Self::AdapterTranscript,
    ];

    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Workspace => b"sley2.workspace.v1",
            Self::Entity => b"sley2.entity.v1",
            Self::Object => b"sley2.object.v1",
            Self::StateRoot => b"sley2.state-root.v1",
            Self::Transaction => b"sley2.transaction.v1",
            Self::Receipt => b"sley2.transaction-receipt.v1",
            Self::SchemaEpoch => b"sley2.schema-epoch.v1",
            Self::PolicyRoot => b"sley2.policy-root.v1",
            Self::CapabilityToken => b"sley2.capability-token.v1",
            Self::Candidate => b"sley2.candidate.v1",
            Self::CandidateResult => b"sley2.candidate-result.v1",
            Self::Query => b"sley2.query.v1",
            Self::ContextCapsule => b"sley2.context-capsule.v1",
            Self::SemanticFingerprint => b"sley2.semantic-fingerprint.v1",
            Self::ValueHash => b"sley2.value-hash.v1",
            Self::BytecodeCacheKey => b"sley2.vm-bytecode-cache-key.v1",
            Self::Observation => b"sley2.observation.v1",
            Self::ExecutionReport => b"sley2.execution-report.v1",
            Self::TestReport => b"sley2.test-report.v1",
            Self::RepositoryPack => b"sley2.repository-pack.v1",
            Self::ProtocolHandshake => b"sley2.protocol-handshake.v1",
            Self::ReferenceAdapter => b"sley2.reference-adapter-id.v1",
            Self::AdapterState => b"sley2.adapter-state.v1",
            Self::AdapterTranscript => b"sley2.adapter-transcript.v1",
        }
    }
}

fn digest(domain: Domain, preimage: &[u8]) -> [u8; ID_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.bytes());
    hasher.update(preimage);
    *hasher.finalize().as_bytes()
}

macro_rules! fixed_bytes_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            /// Constructs this value from exact raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            /// Returns the exact raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }

            /// Returns the exact raw bytes by value.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; ID_LEN] {
                self.0
            }
        }

        impl From<[u8; ID_LEN]> for $name {
            fn from(bytes: [u8; ID_LEN]) -> Self {
                Self::from_bytes(bytes)
            }
        }

        impl From<$name> for [u8; ID_LEN] {
            fn from(value: $name) -> Self {
                value.into_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), short_hex(&self.0))
            }
        }
    };
}

fixed_bytes_type!(
    /// Host-supplied 32-byte workspace genesis nonce.
    GenesisNonce
);
fixed_bytes_type!(
    /// Host-supplied 32-byte entity candidate nonce.
    CandidateNonce
);
fixed_bytes_type!(
    /// Deterministic workspace identifier.
    WorkspaceId
);
fixed_bytes_type!(
    /// Stable logical entity identifier.
    EntityId
);
fixed_bytes_type!(
    /// Immutable semantic object digest.
    ObjectId
);
fixed_bytes_type!(
    /// Semantic state-root digest.
    StateRoot
);
fixed_bytes_type!(
    /// Parent-bound transaction digest.
    TransactionId
);
fixed_bytes_type!(
    /// Complete transaction receipt digest.
    ReceiptId
);
fixed_bytes_type!(
    /// Schema epoch digest.
    SchemaEpochId
);
fixed_bytes_type!(
    /// Protected policy-root digest.
    PolicyRootId
);
fixed_bytes_type!(
    /// Capability-token digest.
    CapabilityTokenDigest
);
fixed_bytes_type!(
    /// Candidate digest.
    CandidateId
);
fixed_bytes_type!(
    /// Candidate-result digest.
    CandidateResultId
);
fixed_bytes_type!(
    /// Typed query digest.
    QueryId
);
fixed_bytes_type!(
    /// Context-capsule digest.
    ContextCapsuleId
);
fixed_bytes_type!(
    /// Semantic fingerprint digest.
    SemanticFingerprint
);
fixed_bytes_type!(
    /// Canonical SSMC value hash.
    ValueHash
);
fixed_bytes_type!(
    /// Derived VM bytecode cache key.
    BytecodeCacheKey
);
fixed_bytes_type!(
    /// Deterministic observation digest.
    ObservationId
);
fixed_bytes_type!(
    /// Execution-report digest.
    ExecutionReportId
);
fixed_bytes_type!(
    /// Test-report digest.
    TestReportId
);
fixed_bytes_type!(
    /// Repository-pack digest.
    RepositoryPackId
);
fixed_bytes_type!(
    /// Protocol-handshake digest.
    ProtocolHandshakeId
);
fixed_bytes_type!(
    /// Restricted reference-adapter identity digest.
    ReferenceAdapterId
);
fixed_bytes_type!(
    /// Complete request-owned adapter fixture-state digest.
    AdapterStateId
);
fixed_bytes_type!(
    /// Restricted reference-adapter invocation transcript digest.
    AdapterTranscriptId
);

impl WorkspaceId {
    /// Derives a workspace identifier from a genesis nonce.
    #[must_use]
    pub fn derive(genesis_nonce: GenesisNonce) -> Self {
        Self(digest(Domain::Workspace, genesis_nonce.as_bytes()))
    }
}

impl EntityId {
    /// Derives an entity identifier from workspace, candidate nonce, kind, and ordinal.
    #[must_use]
    pub fn derive(
        workspace_id: WorkspaceId,
        candidate_nonce: CandidateNonce,
        entity_kind: u32,
        creation_ordinal: u64,
    ) -> Self {
        let mut preimage = [0_u8; 76];
        preimage[..32].copy_from_slice(workspace_id.as_bytes());
        preimage[32..64].copy_from_slice(candidate_nonce.as_bytes());
        preimage[64..68].copy_from_slice(&entity_kind.to_be_bytes());
        preimage[68..76].copy_from_slice(&creation_ordinal.to_be_bytes());
        Self(digest(Domain::Entity, &preimage))
    }
}

macro_rules! digest_type {
    ($name:ident, $domain:expr) => {
        impl $name {
            /// Derives this identifier from its owning contract's canonical preimage.
            #[must_use]
            pub fn derive(preimage: impl AsRef<[u8]>) -> Self {
                Self(digest($domain, preimage.as_ref()))
            }
        }
    };
}

digest_type!(ObjectId, Domain::Object);
digest_type!(StateRoot, Domain::StateRoot);
digest_type!(TransactionId, Domain::Transaction);
digest_type!(ReceiptId, Domain::Receipt);
digest_type!(SchemaEpochId, Domain::SchemaEpoch);
digest_type!(PolicyRootId, Domain::PolicyRoot);
digest_type!(CapabilityTokenDigest, Domain::CapabilityToken);
digest_type!(CandidateId, Domain::Candidate);
digest_type!(CandidateResultId, Domain::CandidateResult);
digest_type!(QueryId, Domain::Query);
digest_type!(ContextCapsuleId, Domain::ContextCapsule);
digest_type!(SemanticFingerprint, Domain::SemanticFingerprint);
digest_type!(ValueHash, Domain::ValueHash);
digest_type!(BytecodeCacheKey, Domain::BytecodeCacheKey);
digest_type!(ObservationId, Domain::Observation);
digest_type!(ExecutionReportId, Domain::ExecutionReport);
digest_type!(TestReportId, Domain::TestReport);
digest_type!(RepositoryPackId, Domain::RepositoryPack);
digest_type!(ProtocolHandshakeId, Domain::ProtocolHandshake);
digest_type!(AdapterStateId, Domain::AdapterState);
digest_type!(AdapterTranscriptId, Domain::AdapterTranscript);

impl ReferenceAdapterId {
    /// Derives a restricted epoch-1 reference adapter identity for one fixed kind.
    #[must_use]
    pub fn derive_kind(kind: u32) -> Self {
        let mut preimage = [0_u8; 16];
        preimage[..8].copy_from_slice(b"SLEYRAI1");
        preimage[8..12].copy_from_slice(&1_u32.to_be_bytes());
        preimage[12..16].copy_from_slice(&kind.to_be_bytes());
        Self(digest(Domain::ReferenceAdapter, &preimage))
    }
}

fn short_hex(bytes: &[u8; ID_LEN]) -> ShortHex<'_> {
    ShortHex(bytes)
}

struct ShortHex<'a>(&'a [u8; ID_LEN]);

impl fmt::Display for ShortHex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: [u8; ID_LEN] = [0; ID_LEN];
    const ONE: [u8; ID_LEN] = [1; ID_LEN];
    const TEST_PREIMAGE: &[u8] = b"sley-id fixed vector preimage";
    const FIXED_VECTORS: [(Domain, &str); 24] = [
        (
            Domain::Workspace,
            "91280bdf6e8df93eafb445c63cf92f0590981d2d9e735d6b01cc9594e0b92f55",
        ),
        (
            Domain::Entity,
            "b560190275b5f814a53fd1dcedb1a34fd4f193b42657913885b04276d3eac8f7",
        ),
        (
            Domain::Object,
            "8db6854150f5b7bb7c0761aca723e0df2db5502b201546cd0d9a1f48dc9c1b34",
        ),
        (
            Domain::StateRoot,
            "c51d96ab7dcaf450158042f880f8f37049b8d03b5bc76a67646518ddfe2abb71",
        ),
        (
            Domain::Transaction,
            "eb303bdb8f39d988302e7e8705b8273cad9c0997ee68cad429ea03afe05003db",
        ),
        (
            Domain::Receipt,
            "b2c84cd8043702498758484841ece39ae37f6f9beb272ca8f3fccf7924f87cfc",
        ),
        (
            Domain::SchemaEpoch,
            "28f53bdf495a33b091f2aae06d7c641bfde944f6cc18450f90c53fb9eddb65a2",
        ),
        (
            Domain::PolicyRoot,
            "ac63bf35c42009268e972e783161c6ffe4080748cbf724079dc3955d8c379d33",
        ),
        (
            Domain::CapabilityToken,
            "1e6d817a18f26baaff8956001fce3cc9679bf1359c6d74ffa780171ff8610287",
        ),
        (
            Domain::Candidate,
            "36fbf7fe85d358cd9f1cf7e35ce052c8a598c40ad9659fcfafe7e8dfffe8ff47",
        ),
        (
            Domain::CandidateResult,
            "a452057435892e8f62b1e1eb802c0119b614e443381161310a92fecb3a8a1593",
        ),
        (
            Domain::Query,
            "a3f0cdf3d7bc9c8327268c819838a874c37f3de6faa0ca7ceb6c30f054e7af26",
        ),
        (
            Domain::ContextCapsule,
            "e8a6f40feeaf2371ce2513ced7a0db5d66b69af2eb9ecc3acc47ed0d978a2c45",
        ),
        (
            Domain::SemanticFingerprint,
            "ff23c3392e7971031f17ec96dcaee0abcec3f7b1d22b4ab5a282582ae8fcc9c2",
        ),
        (
            Domain::ValueHash,
            "76b74346b1c2321cce99039843d3f42a39ab0bc60a8fd2f01484af60134a3e15",
        ),
        (
            Domain::BytecodeCacheKey,
            "6c9848a3ed1b0faa8f745338de0cb1838560e991cd2f277776790eaadd3fb07a",
        ),
        (
            Domain::Observation,
            "11a7eec41c76c6ec99d9d6e066658c61456f389052e5e55a589848904117222b",
        ),
        (
            Domain::ExecutionReport,
            "a5132180a369bab3a21cf9783319017c12606fde58da8b78a4a8683345650011",
        ),
        (
            Domain::TestReport,
            "9dc58bf94c6b61f58ed25cc4038fa82e5a2dc7443a55a6e28e926d38ae644d38",
        ),
        (
            Domain::RepositoryPack,
            "cc14c27bfb954bc2f8eb5779703b929fcfa59ea95d52f606b1181b05be3dbb68",
        ),
        (
            Domain::ProtocolHandshake,
            "8067f7cb688792fb92d7b09b3e47d606170a83e9d6f707c7065a8d8de37f2b0d",
        ),
        (
            Domain::ReferenceAdapter,
            "3e19c93d354bbf7c91c23519a1cef7fa8024a10984cf464704d49708549c2d51",
        ),
        (
            Domain::AdapterState,
            "55bfe9dcac56621c55f1007fbbf50dc5ab8c5047fd86d5654f33ca2e371a15fd",
        ),
        (
            Domain::AdapterTranscript,
            "db2fc017f6456d3347fa9511f2dcfa10fa8379148ecb6e0fc3e433c010c52804",
        ),
    ];

    fn decode_hex_32(hex: &str) -> [u8; ID_LEN] {
        assert_eq!(hex.len(), 64);
        let mut out = [0_u8; ID_LEN];
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            out[index] = u8::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }

    #[test]
    fn frozen_domain_registry_is_exact() {
        let actual: Vec<&'static [u8]> = Domain::ALL.iter().map(|domain| domain.bytes()).collect();
        assert_eq!(
            actual,
            vec![
                b"sley2.workspace.v1".as_slice(),
                b"sley2.entity.v1",
                b"sley2.object.v1",
                b"sley2.state-root.v1",
                b"sley2.transaction.v1",
                b"sley2.transaction-receipt.v1",
                b"sley2.schema-epoch.v1",
                b"sley2.policy-root.v1",
                b"sley2.capability-token.v1",
                b"sley2.candidate.v1",
                b"sley2.candidate-result.v1",
                b"sley2.query.v1",
                b"sley2.context-capsule.v1",
                b"sley2.semantic-fingerprint.v1",
                b"sley2.value-hash.v1",
                b"sley2.vm-bytecode-cache-key.v1",
                b"sley2.observation.v1",
                b"sley2.execution-report.v1",
                b"sley2.test-report.v1",
                b"sley2.repository-pack.v1",
                b"sley2.protocol-handshake.v1",
                b"sley2.reference-adapter-id.v1",
                b"sley2.adapter-state.v1",
                b"sley2.adapter-transcript.v1",
            ]
        );
    }

    #[test]
    fn fixed_vectors_cover_all_domains() {
        assert_eq!(FIXED_VECTORS.len(), Domain::ALL.len());
        for (domain, expected_hex) in FIXED_VECTORS {
            assert_eq!(digest(domain, TEST_PREIMAGE), decode_hex_32(expected_hex));
        }
    }

    #[test]
    fn workspace_and_entity_vectors_are_fixed() {
        let workspace = WorkspaceId::derive(GenesisNonce::from_bytes(ZERO));
        let entity = EntityId::derive(workspace, CandidateNonce::from_bytes(ONE), 7, 42);

        assert_eq!(
            workspace.into_bytes(),
            decode_hex_32("2dc76c67960ad87ee39fe6ff616a5e066b2e0796f6b4bfbe2e5f87d2be438cb8")
        );
        assert_eq!(
            entity.into_bytes(),
            decode_hex_32("6f454113b5ab762721b472327b4e4d0d13d55a92993996fae5c154c3dec0f294")
        );
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(
            ObjectId::derive(TEST_PREIMAGE),
            ObjectId::derive(TEST_PREIMAGE)
        );
        assert_eq!(
            EntityId::derive(
                WorkspaceId::from_bytes(ZERO),
                CandidateNonce::from_bytes(ONE),
                5,
                9
            ),
            EntityId::derive(
                WorkspaceId::from_bytes(ZERO),
                CandidateNonce::from_bytes(ONE),
                5,
                9
            )
        );
    }

    #[test]
    fn perturbing_inputs_changes_derived_ids() {
        assert_ne!(ObjectId::derive(b"a"), ObjectId::derive(b"b"));
        assert_ne!(
            WorkspaceId::derive(GenesisNonce::from_bytes(ZERO)),
            WorkspaceId::derive(GenesisNonce::from_bytes(ONE))
        );
        assert_ne!(
            EntityId::derive(
                WorkspaceId::from_bytes(ZERO),
                CandidateNonce::from_bytes(ONE),
                5,
                9
            ),
            EntityId::derive(
                WorkspaceId::from_bytes(ONE),
                CandidateNonce::from_bytes(ONE),
                5,
                9
            )
        );
        assert_ne!(
            EntityId::derive(
                WorkspaceId::from_bytes(ZERO),
                CandidateNonce::from_bytes(ZERO),
                5,
                9
            ),
            EntityId::derive(
                WorkspaceId::from_bytes(ZERO),
                CandidateNonce::from_bytes(ONE),
                5,
                9
            )
        );
        assert_ne!(
            EntityId::derive(
                WorkspaceId::from_bytes(ZERO),
                CandidateNonce::from_bytes(ONE),
                5,
                9
            ),
            EntityId::derive(
                WorkspaceId::from_bytes(ZERO),
                CandidateNonce::from_bytes(ONE),
                6,
                9
            )
        );
        assert_ne!(
            EntityId::derive(
                WorkspaceId::from_bytes(ZERO),
                CandidateNonce::from_bytes(ONE),
                5,
                9
            ),
            EntityId::derive(
                WorkspaceId::from_bytes(ZERO),
                CandidateNonce::from_bytes(ONE),
                5,
                10
            )
        );
    }

    #[test]
    fn identifier_types_are_exactly_32_bytes() {
        assert_eq!(core::mem::size_of::<GenesisNonce>(), ID_LEN);
        assert_eq!(core::mem::size_of::<CandidateNonce>(), ID_LEN);
        assert_eq!(core::mem::size_of::<WorkspaceId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<EntityId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<ObjectId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<StateRoot>(), ID_LEN);
        assert_eq!(core::mem::size_of::<TransactionId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<ReceiptId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<SchemaEpochId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<PolicyRootId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<CapabilityTokenDigest>(), ID_LEN);
        assert_eq!(core::mem::size_of::<CandidateId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<CandidateResultId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<QueryId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<ContextCapsuleId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<SemanticFingerprint>(), ID_LEN);
        assert_eq!(core::mem::size_of::<ValueHash>(), ID_LEN);
        assert_eq!(core::mem::size_of::<BytecodeCacheKey>(), ID_LEN);
        assert_eq!(core::mem::size_of::<ObservationId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<ExecutionReportId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<TestReportId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<RepositoryPackId>(), ID_LEN);
        assert_eq!(core::mem::size_of::<ProtocolHandshakeId>(), ID_LEN);
    }

    #[test]
    fn debug_output_is_non_canonical_short_form() {
        let debug = format!("{:?}", ObjectId::from_bytes([0xab; ID_LEN]));
        assert_eq!(debug, "ObjectId(abababab..)");
    }
}
