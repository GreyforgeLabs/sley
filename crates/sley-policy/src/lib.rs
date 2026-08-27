#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]
#![doc = include_str!("../README.md")]

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use sley_check::contracts::{ContractTestReport, TestPlanFinality};
use sley_id::{
    CapabilityTokenDigest, EntityId, PolicyRootId, PrincipalId, ReferenceAdapterId, SchemaEpochId,
    StateRoot, ValueHash, WorkspaceId,
};
use sley_mutate::MutationClass;
use sley_scb1::{
    MAX_COLLECTION_ELEMENTS, MAX_RECORD_FIELDS, MAX_STANDALONE_BYTES, ScbError, ScbErrorCode,
    encode_list, encode_map, encode_option_uvar, encode_record, encode_union, encode_uvar,
};
use sley_schema::{
    ContractDescriptor, EpochDecodeError, EpochDecoder, EpochLimits, RegistryEntry,
    SchemaEpochRecordV1, SchemaEpochRegistry, SchemaError, SchemaErrorCode, UnicodeVersion,
};
use sley_ssmc::EffectKind;
use sley_state_root::AcceptedStateRoot;

const MAGIC: &[u8; 8] = b"SLEYSCB1";
const FORMAT_VERSION: u64 = 1;
const CONTRACT_TAG: u32 = 370;
const DIGEST_DOMAIN_TAG: u32 = 8;
const KIND_TAG: u32 = 370;
const ID_LEN: usize = 32;
const FIELD_COUNT: u64 = 11;
const GRANT_FIELD_COUNT: u64 = 4;
const RESOURCE_FIELD_COUNT: u64 = 6;
const CAPABILITY_TOKEN_FIELD_COUNT: u64 = 16;
const CAPABILITY_BUDGET_FIELD_COUNT: u64 = 6;
const POLICY_SCHEMA_VERSION: u32 = 1;
const TRANSITION_MODE_EXTERNAL_HIGHER_AUTHORITY_ONLY: u32 = 1;
const CAPABILITY_TOKEN_VERSION: u32 = 1;
const CAPABILITY_DIGEST_MAGIC: &[u8; 8] = b"SLEYCAPD";
const CAPABILITY_MAC_MAGIC: &[u8; 8] = b"SLEYCAPM";

/// Maximum principal grants in one S20-370 root.
pub const MAX_POLICY_PRINCIPAL_GRANTS: usize = 65_535;
/// Maximum effect-kind or mutation-class tags in one grant.
pub const MAX_POLICY_GRANT_TAGS: usize = 4_096;
/// Maximum adapter identities in one grant.
pub const MAX_POLICY_GRANT_ADAPTERS: usize = 65_535;
/// Maximum protected entity identities in one root.
pub const MAX_POLICY_PROTECTED_ENTITIES: usize = 65_535;
/// Maximum required test identities in one root or final plan.
pub const MAX_POLICY_REQUIRED_TESTS: usize = 65_535;
/// Maximum required contract identities in one root or final plan.
pub const MAX_POLICY_REQUIRED_CONTRACTS: usize = 65_535;
/// Maximum literal value accepted for one policy resource ceiling.
pub const MAX_POLICY_RESOURCE_CEILING: u64 = 1_000_000_000_000_000;

/// Exact descriptor preimage for the S20-370 field schema hash.
pub const FIELD_SCHEMA_PREIMAGE: &str = "sley2.policy-root.v1.schema:required(1:workspace_id fixed32,2:schema_epoch_id fixed32,3:policy_schema_version u32,4:parent_policy option fixed32,5:principal_grants map fixed32 record(1:allowed_effect_kind_tags set u32,2:allowed_mutation_class_tags set u32,3:allowed_adapter_ids set fixed32,4:resource_ceilings record(1:max_fuel u64,2:max_memory_bytes u64,3:max_output_bytes u64,4:max_effect_count u64,5:max_mutation_count u64,6:max_adapter_calls u64)),6:protected_entities set fixed32,7:required_tests set fixed32,8:required_contracts set fixed32,9:expiry_unix_millis option u64,10:transition_mode u32,11:interpretation_flags set u32);flags=empty;transition=external-higher-authority-only;epoch=1";
/// Exact descriptor preimage for the S20-370 decoder-limits hash.
pub const DECODER_LIMITS_PREIMAGE: &str = "sley2.policy-root.v1.decoder-limits:scb1-epoch1;principal-grants=65535;grant-tags=4096;grant-adapters=65535;protected-entities=65535;required-tests=65535;required-contracts=65535;max-resource-ceiling=1000000000000000";

const FIELD_SCHEMA_HASH: [u8; ID_LEN] = [
    0x18, 0xc1, 0x24, 0xc2, 0x67, 0xde, 0x22, 0x8e, 0x79, 0x93, 0x6a, 0x01, 0xe5, 0x89, 0xae, 0xda,
    0xfe, 0x57, 0x6b, 0x8d, 0x0f, 0xdf, 0x61, 0x1f, 0x12, 0xd5, 0x17, 0xf0, 0x37, 0x8a, 0xa3, 0x35,
];
const DECODER_LIMITS_HASH: [u8; ID_LEN] = [
    0xca, 0x84, 0xd0, 0xb5, 0xc4, 0x91, 0x1b, 0xff, 0x88, 0xc6, 0xf5, 0xed, 0x7c, 0x93, 0xe8, 0xf1,
    0xeb, 0x6e, 0xf1, 0x6b, 0x91, 0x93, 0xf5, 0x30, 0x20, 0xa5, 0x64, 0x9c, 0x01, 0x30, 0x67, 0x25,
];

/// Stable S20-370 protected policy-root failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRootErrorCode {
    /// `POLICY_ROOT_DUPLICATE_INPUT`
    DuplicateInput,
    /// `POLICY_ROOT_VERSION_UNSUPPORTED`
    VersionUnsupported,
    /// `POLICY_ROOT_EFFECT_KIND_UNKNOWN`
    EffectKindUnknown,
    /// `POLICY_ROOT_MUTATION_CLASS_UNKNOWN`
    MutationClassUnknown,
    /// `POLICY_ROOT_RESOURCE_LIMIT`
    ResourceLimit,
    /// `POLICY_ROOT_TRANSITION_MODE_INVALID`
    TransitionModeInvalid,
    /// `POLICY_ROOT_FLAG_UNKNOWN`
    FlagUnknown,
    /// `POLICY_GRANT_DENIED`
    GrantDenied,
    /// `POLICY_ISOLATION_POLICY_ROOT_MISMATCH`
    PolicyRootMismatch,
    /// `POLICY_ISOLATION_WORKSPACE_MISMATCH`
    WorkspaceMismatch,
    /// `POLICY_ISOLATION_POLICY_ROOT_CHANGED`
    StatePolicyRootChanged,
    /// `POLICY_ISOLATION_SCHEMA_EPOCH_CHANGED`
    StateSchemaEpochChanged,
    /// `POLICY_ISOLATION_CONTRACT_ROOT_CHANGED`
    StateContractRootChanged,
    /// `POLICY_ISOLATION_TEST_ROOT_CHANGED`
    StateTestRootChanged,
    /// `POLICY_ISOLATION_PROTECTED_ENTITY_CHANGED`
    ProtectedEntityChanged,
    /// `POLICY_FINAL_REPORT_INVALID`
    FinalReportInvalid,
    /// `POLICY_FINAL_REQUIRED_TEST_MISSING`
    RequiredTestMissing,
    /// `POLICY_FINAL_REQUIRED_CONTRACT_MISSING`
    RequiredContractMissing,
    /// `POLICY_FINAL_REQUIRED_TEST_NOT_SELECTED`
    RequiredTestNotSelected,
}

impl PolicyRootErrorCode {
    /// Returns the exact stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateInput => "POLICY_ROOT_DUPLICATE_INPUT",
            Self::VersionUnsupported => "POLICY_ROOT_VERSION_UNSUPPORTED",
            Self::EffectKindUnknown => "POLICY_ROOT_EFFECT_KIND_UNKNOWN",
            Self::MutationClassUnknown => "POLICY_ROOT_MUTATION_CLASS_UNKNOWN",
            Self::ResourceLimit => "POLICY_ROOT_RESOURCE_LIMIT",
            Self::TransitionModeInvalid => "POLICY_ROOT_TRANSITION_MODE_INVALID",
            Self::FlagUnknown => "POLICY_ROOT_FLAG_UNKNOWN",
            Self::GrantDenied => "POLICY_GRANT_DENIED",
            Self::PolicyRootMismatch => "POLICY_ISOLATION_POLICY_ROOT_MISMATCH",
            Self::WorkspaceMismatch => "POLICY_ISOLATION_WORKSPACE_MISMATCH",
            Self::StatePolicyRootChanged => "POLICY_ISOLATION_POLICY_ROOT_CHANGED",
            Self::StateSchemaEpochChanged => "POLICY_ISOLATION_SCHEMA_EPOCH_CHANGED",
            Self::StateContractRootChanged => "POLICY_ISOLATION_CONTRACT_ROOT_CHANGED",
            Self::StateTestRootChanged => "POLICY_ISOLATION_TEST_ROOT_CHANGED",
            Self::ProtectedEntityChanged => "POLICY_ISOLATION_PROTECTED_ENTITY_CHANGED",
            Self::FinalReportInvalid => "POLICY_FINAL_REPORT_INVALID",
            Self::RequiredTestMissing => "POLICY_FINAL_REQUIRED_TEST_MISSING",
            Self::RequiredContractMissing => "POLICY_FINAL_REQUIRED_CONTRACT_MISSING",
            Self::RequiredTestNotSelected => "POLICY_FINAL_REQUIRED_TEST_NOT_SELECTED",
        }
    }

    /// Returns the exact stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::DuplicateInput => 37_000,
            Self::VersionUnsupported => 37_001,
            Self::EffectKindUnknown => 37_002,
            Self::MutationClassUnknown => 37_003,
            Self::ResourceLimit => 37_004,
            Self::TransitionModeInvalid => 37_005,
            Self::FlagUnknown => 37_006,
            Self::GrantDenied => 37_007,
            Self::PolicyRootMismatch => 37_008,
            Self::WorkspaceMismatch => 37_009,
            Self::StatePolicyRootChanged => 37_010,
            Self::StateSchemaEpochChanged => 37_011,
            Self::StateContractRootChanged => 37_012,
            Self::StateTestRootChanged => 37_013,
            Self::ProtectedEntityChanged => 37_014,
            Self::FinalReportInvalid => 37_015,
            Self::RequiredTestMissing => 37_016,
            Self::RequiredContractMissing => 37_017,
            Self::RequiredTestNotSelected => 37_018,
        }
    }
}

impl fmt::Display for PolicyRootErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Exact S20-370 failure preserving schema and SCB1 errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyRootError {
    /// Protected policy-root semantic validation failed.
    PolicyRoot(PolicyRootErrorCode),
    /// Registry or descriptor authorization failed.
    Schema(SchemaError),
    /// Canonical byte decoding failed.
    Scb(ScbError),
}

impl PolicyRootError {
    /// Returns the stable failure string without collapsing its source.
    #[must_use]
    pub fn code_str(&self) -> &'static str {
        match self {
            Self::PolicyRoot(code) => code.as_str(),
            Self::Schema(error) => error.code().as_str(),
            Self::Scb(error) => error.code().as_str(),
        }
    }
}

impl fmt::Display for PolicyRootError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_str())
    }
}

impl std::error::Error for PolicyRootError {}

impl From<ScbError> for PolicyRootError {
    fn from(value: ScbError) -> Self {
        Self::Scb(value)
    }
}

impl From<SchemaError> for PolicyRootError {
    fn from(value: SchemaError) -> Self {
        Self::Schema(value)
    }
}

impl From<EpochDecodeError> for PolicyRootError {
    fn from(value: EpochDecodeError) -> Self {
        match value {
            EpochDecodeError::Schema(error) => Self::Schema(error),
            EpochDecodeError::Scb(error) => Self::Scb(error),
        }
    }
}

/// Exact resource ceilings bound to one principal grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyResourceCeilings {
    /// Maximum execution fuel.
    pub max_fuel: u64,
    /// Maximum memory bytes.
    pub max_memory_bytes: u64,
    /// Maximum output bytes.
    pub max_output_bytes: u64,
    /// Maximum effect operations.
    pub max_effect_count: u64,
    /// Maximum mutation operations.
    pub max_mutation_count: u64,
    /// Maximum adapter calls.
    pub max_adapter_calls: u64,
}

impl PolicyResourceCeilings {
    /// Constructs exact literal ceilings.
    #[must_use]
    pub const fn new(
        max_fuel: u64,
        max_memory_bytes: u64,
        max_output_bytes: u64,
        max_effect_count: u64,
        max_mutation_count: u64,
        max_adapter_calls: u64,
    ) -> Self {
        Self {
            max_fuel,
            max_memory_bytes,
            max_output_bytes,
            max_effect_count,
            max_mutation_count,
            max_adapter_calls,
        }
    }

    /// Returns a grant with every ceiling set to zero.
    #[must_use]
    pub const fn zero() -> Self {
        Self::new(0, 0, 0, 0, 0, 0)
    }

    fn validate(self) -> Result<(), PolicyRootErrorCode> {
        if [
            self.max_fuel,
            self.max_memory_bytes,
            self.max_output_bytes,
            self.max_effect_count,
            self.max_mutation_count,
            self.max_adapter_calls,
        ]
        .into_iter()
        .all(|value| value <= MAX_POLICY_RESOURCE_CEILING)
        {
            Ok(())
        } else {
            Err(PolicyRootErrorCode::ResourceLimit)
        }
    }
}

/// Stable S20-380 capability-token and runtime-ledger failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CapabilityErrorCode {
    /// `CAP_VERSION_UNSUPPORTED`
    VersionUnsupported = 38_000,
    /// `CAP_ISSUER_UNTRUSTED`
    IssuerUntrusted = 38_001,
    /// `CAP_KEY_UNTRUSTED`
    KeyUntrusted = 38_002,
    /// `CAP_AUTHENTICATOR_INVALID`
    AuthenticatorInvalid = 38_003,
    /// `CAP_POLICY_ROOT_MISMATCH`
    PolicyRootMismatch = 38_004,
    /// `CAP_WORKSPACE_MISMATCH`
    WorkspaceMismatch = 38_005,
    /// `CAP_PRINCIPAL_MISMATCH`
    PrincipalMismatch = 38_006,
    /// `CAP_STATE_ROOT_MISMATCH`
    StateRootMismatch = 38_007,
    /// `CAP_EFFECT_MISMATCH`
    EffectMismatch = 38_008,
    /// `CAP_SCOPE_MISMATCH`
    ScopeMismatch = 38_009,
    /// `CAP_ADAPTER_MISMATCH`
    AdapterMismatch = 38_010,
    /// `CAP_EXPIRED`
    Expired = 38_011,
    /// `CAP_TIME_INVALID`
    TimeInvalid = 38_012,
    /// `CAP_BUDGET_ZERO`
    BudgetZero = 38_013,
    /// `CAP_BUDGET_EXCEEDED`
    BudgetExceeded = 38_014,
    /// `CAP_GRANT_DENIED`
    GrantDenied = 38_015,
    /// `CAP_REPLAY`
    Replay = 38_016,
    /// `CAP_LEDGER_EXHAUSTED`
    LedgerExhausted = 38_017,
    /// `CAP_CANONICAL_INVALID`
    CanonicalInvalid = 38_018,
    /// `CAP_INTERNAL_INVARIANT`
    InternalInvariant = 38_019,
}

impl CapabilityErrorCode {
    /// Returns the exact stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VersionUnsupported => "CAP_VERSION_UNSUPPORTED",
            Self::IssuerUntrusted => "CAP_ISSUER_UNTRUSTED",
            Self::KeyUntrusted => "CAP_KEY_UNTRUSTED",
            Self::AuthenticatorInvalid => "CAP_AUTHENTICATOR_INVALID",
            Self::PolicyRootMismatch => "CAP_POLICY_ROOT_MISMATCH",
            Self::WorkspaceMismatch => "CAP_WORKSPACE_MISMATCH",
            Self::PrincipalMismatch => "CAP_PRINCIPAL_MISMATCH",
            Self::StateRootMismatch => "CAP_STATE_ROOT_MISMATCH",
            Self::EffectMismatch => "CAP_EFFECT_MISMATCH",
            Self::ScopeMismatch => "CAP_SCOPE_MISMATCH",
            Self::AdapterMismatch => "CAP_ADAPTER_MISMATCH",
            Self::Expired => "CAP_EXPIRED",
            Self::TimeInvalid => "CAP_TIME_INVALID",
            Self::BudgetZero => "CAP_BUDGET_ZERO",
            Self::BudgetExceeded => "CAP_BUDGET_EXCEEDED",
            Self::GrantDenied => "CAP_GRANT_DENIED",
            Self::Replay => "CAP_REPLAY",
            Self::LedgerExhausted => "CAP_LEDGER_EXHAUSTED",
            Self::CanonicalInvalid => "CAP_CANONICAL_INVALID",
            Self::InternalInvariant => "CAP_INTERNAL_INVARIANT",
        }
    }

    /// Returns the exact stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        self as u32
    }
}

impl fmt::Display for CapabilityErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Exact S20-380 failure preserving SCB1 canonical decoding failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    /// Capability-token, MAC, request, or ledger judgment failed.
    Capability(CapabilityErrorCode),
    /// Canonical byte decoding failed.
    Scb(ScbError),
}

impl CapabilityError {
    /// Returns the stable failure string without collapsing its source.
    #[must_use]
    pub fn code_str(&self) -> &'static str {
        match self {
            Self::Capability(code) => code.as_str(),
            Self::Scb(error) => error.code().as_str(),
        }
    }
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_str())
    }
}

impl std::error::Error for CapabilityError {}

impl From<ScbError> for CapabilityError {
    fn from(value: ScbError) -> Self {
        Self::Scb(value)
    }
}

macro_rules! capability_fixed_type {
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
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "{}({})",
                    stringify!($name),
                    capability_short_hex(&self.0)
                )
            }
        }
    };
}

capability_fixed_type!(
    /// Opaque host-supplied 32-byte capability issuer identity.
    CapabilityIssuerId
);
capability_fixed_type!(
    /// Opaque host-supplied 32-byte capability MAC key identity.
    CapabilityKeyId
);
capability_fixed_type!(
    /// Opaque 32-byte nonce bound into one capability token body.
    CapabilityTokenNonce
);
capability_fixed_type!(
    /// Opaque 32-byte caller-owned nonce for one charged capability use.
    CapabilityUseNonce
);
capability_fixed_type!(
    /// Opaque 32-byte keyed BLAKE3 authenticator.
    CapabilityAuthenticator
);

/// Host-supplied 32-byte keyed BLAKE3 secret. It is never serialized.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CapabilitySecret([u8; ID_LEN]);

impl CapabilitySecret {
    /// Constructs a secret from exact host-owned bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }
}

impl fmt::Debug for CapabilitySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilitySecret(..redacted..)")
    }
}

/// One trusted issuer/key/secret tuple supplied explicitly by the host.
#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityTrustedKey {
    /// Trusted issuer identity.
    pub issuer_id: CapabilityIssuerId,
    /// Trusted key identity for the issuer.
    pub key_id: CapabilityKeyId,
    secret: CapabilitySecret,
}

impl CapabilityTrustedKey {
    /// Constructs one trusted keyed-BLAKE3 verifier input.
    #[must_use]
    pub const fn new(
        issuer_id: CapabilityIssuerId,
        key_id: CapabilityKeyId,
        secret: CapabilitySecret,
    ) -> Self {
        Self {
            issuer_id,
            key_id,
            secret,
        }
    }

    fn secret(&self) -> CapabilitySecret {
        self.secret
    }
}

impl fmt::Debug for CapabilityTrustedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityTrustedKey")
            .field("issuer_id", &self.issuer_id)
            .field("key_id", &self.key_id)
            .field("secret", &self.secret)
            .finish()
    }
}

/// Frozen six-field runtime budget vector coherent with `PolicyResourceCeilings`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapabilityResourceBudget {
    /// Maximum execution fuel.
    pub max_fuel: u64,
    /// Maximum memory bytes.
    pub max_memory_bytes: u64,
    /// Maximum output bytes.
    pub max_output_bytes: u64,
    /// Maximum effect operations.
    pub max_effect_count: u64,
    /// Maximum mutation operations.
    pub max_mutation_count: u64,
    /// Maximum adapter calls.
    pub max_adapter_calls: u64,
}

impl CapabilityResourceBudget {
    /// Constructs exact literal budget values.
    #[must_use]
    pub const fn new(
        max_fuel: u64,
        max_memory_bytes: u64,
        max_output_bytes: u64,
        max_effect_count: u64,
        max_mutation_count: u64,
        max_adapter_calls: u64,
    ) -> Self {
        Self {
            max_fuel,
            max_memory_bytes,
            max_output_bytes,
            max_effect_count,
            max_mutation_count,
            max_adapter_calls,
        }
    }

    /// Returns an all-zero budget.
    #[must_use]
    pub const fn zero() -> Self {
        Self::new(0, 0, 0, 0, 0, 0)
    }

    /// Returns the frozen charge for one authorized reference-adapter dispatch.
    #[must_use]
    pub const fn adapter_invocation() -> Self {
        Self::new(0, 0, 0, 1, 0, 1)
    }

    /// Returns whether all budget dimensions are zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.max_fuel == 0
            && self.max_memory_bytes == 0
            && self.max_output_bytes == 0
            && self.max_effect_count == 0
            && self.max_mutation_count == 0
            && self.max_adapter_calls == 0
    }

    fn validate_nonzero(self) -> Result<(), CapabilityErrorCode> {
        if self.is_zero() {
            return Err(CapabilityErrorCode::BudgetZero);
        }
        if [
            self.max_fuel,
            self.max_memory_bytes,
            self.max_output_bytes,
            self.max_effect_count,
            self.max_mutation_count,
            self.max_adapter_calls,
        ]
        .into_iter()
        .all(|value| value <= MAX_POLICY_RESOURCE_CEILING)
        {
            Ok(())
        } else {
            Err(CapabilityErrorCode::BudgetExceeded)
        }
    }

    fn fits_within_ceilings(self, ceilings: PolicyResourceCeilings) -> bool {
        self.max_fuel <= ceilings.max_fuel
            && self.max_memory_bytes <= ceilings.max_memory_bytes
            && self.max_output_bytes <= ceilings.max_output_bytes
            && self.max_effect_count <= ceilings.max_effect_count
            && self.max_mutation_count <= ceilings.max_mutation_count
            && self.max_adapter_calls <= ceilings.max_adapter_calls
    }

    fn fits_within(self, limit: Self) -> bool {
        self.max_fuel <= limit.max_fuel
            && self.max_memory_bytes <= limit.max_memory_bytes
            && self.max_output_bytes <= limit.max_output_bytes
            && self.max_effect_count <= limit.max_effect_count
            && self.max_mutation_count <= limit.max_mutation_count
            && self.max_adapter_calls <= limit.max_adapter_calls
    }

    fn checked_add(self, amount: Self) -> Option<Self> {
        Some(Self {
            max_fuel: self.max_fuel.checked_add(amount.max_fuel)?,
            max_memory_bytes: self.max_memory_bytes.checked_add(amount.max_memory_bytes)?,
            max_output_bytes: self.max_output_bytes.checked_add(amount.max_output_bytes)?,
            max_effect_count: self.max_effect_count.checked_add(amount.max_effect_count)?,
            max_mutation_count: self
                .max_mutation_count
                .checked_add(amount.max_mutation_count)?,
            max_adapter_calls: self
                .max_adapter_calls
                .checked_add(amount.max_adapter_calls)?,
        })
    }

    fn checked_sub(self, amount: Self) -> Option<Self> {
        Some(Self {
            max_fuel: self.max_fuel.checked_sub(amount.max_fuel)?,
            max_memory_bytes: self.max_memory_bytes.checked_sub(amount.max_memory_bytes)?,
            max_output_bytes: self.max_output_bytes.checked_sub(amount.max_output_bytes)?,
            max_effect_count: self.max_effect_count.checked_sub(amount.max_effect_count)?,
            max_mutation_count: self
                .max_mutation_count
                .checked_sub(amount.max_mutation_count)?,
            max_adapter_calls: self
                .max_adapter_calls
                .checked_sub(amount.max_adapter_calls)?,
        })
    }
}

/// Unauthenticated canonical S20-380 capability-token body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityTokenBody {
    /// Frozen token version. Epoch 1 accepts only `1`.
    pub version: u32,
    /// Opaque issuer identity.
    pub issuer_id: CapabilityIssuerId,
    /// Opaque issuer key identity.
    pub key_id: CapabilityKeyId,
    /// Exact principal identity.
    pub principal_id: PrincipalId,
    /// Exact workspace identity.
    pub workspace_id: WorkspaceId,
    /// Exact accepted semantic state root.
    pub state_root: StateRoot,
    /// Exact effect-definition entity.
    pub effect_id: EntityId,
    /// Frozen SSMC1 `EffectKind` tag.
    pub effect_kind_tag: u32,
    /// Canonical SSMC1 resource-scope `ValueHash`.
    pub scope_hash: ValueHash,
    /// Exact reference-adapter identity.
    pub adapter_id: ReferenceAdapterId,
    /// Bounded runtime resource budget.
    pub budget: CapabilityResourceBudget,
    /// Exact issuance time supplied by the host.
    pub issued_unix_millis: u64,
    /// Exact exclusive expiry time supplied by the host.
    pub expiry_unix_millis: u64,
    /// Opaque per-token nonce.
    pub token_nonce: CapabilityTokenNonce,
    /// Exact accepted protected policy root.
    pub policy_root: PolicyRootId,
}

/// Authenticated S20-380 capability token and its exact canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityToken {
    body: CapabilityTokenBody,
    digest: CapabilityTokenDigest,
    authenticator: CapabilityAuthenticator,
    stored_bytes: Vec<u8>,
}

impl CapabilityToken {
    /// Returns the unauthenticated canonical token body.
    #[must_use]
    pub const fn body(&self) -> &CapabilityTokenBody {
        &self.body
    }

    /// Returns the digest of the unauthenticated canonical body.
    #[must_use]
    pub const fn digest(&self) -> CapabilityTokenDigest {
        self.digest
    }

    /// Returns the keyed BLAKE3 authenticator bytes.
    #[must_use]
    pub const fn authenticator(&self) -> CapabilityAuthenticator {
        self.authenticator
    }

    /// Returns the exact canonical SCB1 token bytes.
    #[must_use]
    pub fn stored_bytes(&self) -> &[u8] {
        &self.stored_bytes
    }
}

/// Host request to issue one local S20-380 token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityTokenRequest {
    /// Principal that receives the token.
    pub principal_id: PrincipalId,
    /// Workspace the token is bound to.
    pub workspace_id: WorkspaceId,
    /// Exact state root the token may authorize.
    pub state_root: StateRoot,
    /// Exact effect definition the token may authorize.
    pub effect_id: EntityId,
    /// Exact effect kind the token may authorize.
    pub effect_kind: EffectKind,
    /// Exact canonical resource-scope hash.
    pub scope_hash: ValueHash,
    /// Exact reference adapter identity.
    pub adapter_id: ReferenceAdapterId,
    /// Bounded resource budget.
    pub budget: CapabilityResourceBudget,
    /// Host-supplied issuance time.
    pub now_unix_millis: u64,
    /// Host-supplied exclusive expiry time.
    pub expiry_unix_millis: u64,
    /// Host-supplied opaque token nonce.
    pub token_nonce: CapabilityTokenNonce,
}

/// Runtime request that a token must exactly authorize.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityVerificationRequest {
    /// Principal attempting to use the token.
    pub principal_id: PrincipalId,
    /// Workspace of the attempted use.
    pub workspace_id: WorkspaceId,
    /// Exact state root of the attempted use.
    pub state_root: StateRoot,
    /// Exact effect definition of the attempted use.
    pub effect_id: EntityId,
    /// Exact effect kind of the attempted use.
    pub effect_kind: EffectKind,
    /// Exact resource scope of the attempted use.
    pub scope_hash: ValueHash,
    /// Exact adapter identity of the attempted use.
    pub adapter_id: ReferenceAdapterId,
    /// Explicit host-supplied verification time.
    pub now_unix_millis: u64,
    /// Resource amount that must remain available for this use.
    pub required_budget: CapabilityResourceBudget,
}

/// Receipt for one atomic capability-ledger charge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityChargeReceipt {
    /// Token digest charged by this use.
    pub token_digest: CapabilityTokenDigest,
    /// Exact per-use nonce charged by this use.
    pub use_nonce: CapabilityUseNonce,
    /// Budget charged.
    pub charged: CapabilityResourceBudget,
    /// Cumulative budget spent after the charge.
    pub spent_after: CapabilityResourceBudget,
    /// Remaining token budget after the charge.
    pub remaining_after: CapabilityResourceBudget,
}

/// Deterministic caller-owned replay and budget ledger.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapabilityLedger {
    spent: BTreeMap<CapabilityTokenDigest, CapabilityResourceBudget>,
    use_nonces: BTreeSet<(CapabilityTokenDigest, CapabilityUseNonce)>,
}

impl CapabilityLedger {
    /// Creates an empty caller-owned ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns cumulative spend for one token digest.
    #[must_use]
    pub fn spent(&self, token_digest: CapabilityTokenDigest) -> CapabilityResourceBudget {
        self.spent
            .get(&token_digest)
            .copied()
            .unwrap_or_else(CapabilityResourceBudget::zero)
    }

    /// Returns whether this exact token/use nonce has already been charged.
    #[must_use]
    pub fn has_use_nonce(
        &self,
        token_digest: CapabilityTokenDigest,
        use_nonce: CapabilityUseNonce,
    ) -> bool {
        self.use_nonces.contains(&(token_digest, use_nonce))
    }

    /// Atomically charges one exact token/use nonce.
    ///
    /// # Errors
    ///
    /// Returns `CAP_REPLAY` for a reused use nonce and does not mutate the
    /// ledger. Returns a budget error without mutation if the token budget
    /// cannot cover the charge.
    pub fn charge(
        &mut self,
        token: &CapabilityToken,
        use_nonce: CapabilityUseNonce,
        amount: CapabilityResourceBudget,
    ) -> Result<CapabilityChargeReceipt, CapabilityError> {
        amount
            .validate_nonzero()
            .map_err(CapabilityError::Capability)?;
        let token_digest = token.digest();
        if self.use_nonces.contains(&(token_digest, use_nonce)) {
            return capability_fail(CapabilityErrorCode::Replay);
        }
        let spent_before = self.spent(token_digest);
        let spent_after = spent_before
            .checked_add(amount)
            .ok_or(CapabilityErrorCode::LedgerExhausted)
            .map_err(CapabilityError::Capability)?;
        if !spent_after.fits_within(token.body.budget) {
            return capability_fail(CapabilityErrorCode::LedgerExhausted);
        }
        let remaining_after = token
            .body
            .budget
            .checked_sub(spent_after)
            .ok_or(CapabilityErrorCode::InternalInvariant)
            .map_err(CapabilityError::Capability)?;
        self.use_nonces.insert((token_digest, use_nonce));
        self.spent.insert(token_digest, spent_after);
        Ok(CapabilityChargeReceipt {
            token_digest,
            use_nonce,
            charged: amount,
            spent_after,
            remaining_after,
        })
    }
}

/// Issues one local-only authenticated capability token.
///
/// # Errors
///
/// Returns a stable S20-380 failure when the accepted policy root, principal
/// grant, effect, adapter, time ordering, or budget does not authorize the
/// request.
pub fn issue_capability_token(
    policy: &AcceptedPolicyRoot,
    trusted_key: &CapabilityTrustedKey,
    request: &CapabilityTokenRequest,
) -> Result<CapabilityToken, CapabilityError> {
    let body = CapabilityTokenBody {
        version: CAPABILITY_TOKEN_VERSION,
        issuer_id: trusted_key.issuer_id,
        key_id: trusted_key.key_id,
        principal_id: request.principal_id,
        workspace_id: request.workspace_id,
        state_root: request.state_root,
        effect_id: request.effect_id,
        effect_kind_tag: request.effect_kind.tag(),
        scope_hash: request.scope_hash,
        adapter_id: request.adapter_id,
        budget: request.budget,
        issued_unix_millis: request.now_unix_millis,
        expiry_unix_millis: request.expiry_unix_millis,
        token_nonce: request.token_nonce,
        policy_root: policy.root(),
    };
    validate_capability_body_shape(&body)?;
    validate_capability_policy_binding(policy, &body, body.issued_unix_millis)?;
    finish_capability_token(body, trusted_key)
}

/// Imports exact canonical S20-380 token bytes without trusting the MAC.
///
/// # Errors
///
/// Returns SCB1 or capability canonical-shape failures. Call
/// [`verify_capability_token`] before treating the token as authority.
pub fn import_capability_token(input: &[u8]) -> Result<CapabilityToken, CapabilityError> {
    let (body, authenticator) = decode_capability_token_record(input)?;
    validate_capability_body_shape(&body)?;
    let body_bytes = encode_capability_body_record(&body)?;
    let digest = capability_token_digest(&body_bytes)?;
    let canonical = encode_capability_token_record(&body, authenticator)?;
    if canonical != input {
        return capability_fail(CapabilityErrorCode::CanonicalInvalid);
    }
    Ok(CapabilityToken {
        body,
        digest,
        authenticator,
        stored_bytes: canonical,
    })
}

/// Verifies MAC, trusted issuer/key, policy, exact request, time, and budget.
///
/// # Errors
///
/// Returns the first deterministic S20-380 failure. Verification never mutates
/// a ledger.
pub fn verify_capability_token(
    policy: &AcceptedPolicyRoot,
    token: &CapabilityToken,
    trusted_key: &CapabilityTrustedKey,
    request: &CapabilityVerificationRequest,
) -> Result<CapabilityTokenDigest, CapabilityError> {
    validate_capability_body_shape(&token.body)?;
    if token.body.issuer_id != trusted_key.issuer_id {
        return capability_fail(CapabilityErrorCode::IssuerUntrusted);
    }
    if token.body.key_id != trusted_key.key_id {
        return capability_fail(CapabilityErrorCode::KeyUntrusted);
    }
    let body_bytes = encode_capability_body_record(&token.body)?;
    let digest = capability_token_digest(&body_bytes)?;
    if digest != token.digest {
        return capability_fail(CapabilityErrorCode::CanonicalInvalid);
    }
    let expected =
        capability_authenticator(trusted_key.secret(), &token.body, digest, &body_bytes)?;
    if !constant_time_eq(expected.as_bytes(), token.authenticator.as_bytes()) {
        return capability_fail(CapabilityErrorCode::AuthenticatorInvalid);
    }
    validate_capability_request_binding(policy, &token.body, request)?;
    validate_capability_policy_binding(policy, &token.body, request.now_unix_millis)?;
    request
        .required_budget
        .validate_nonzero()
        .map_err(CapabilityError::Capability)?;
    if !request.required_budget.fits_within(token.body.budget) {
        return capability_fail(CapabilityErrorCode::BudgetExceeded);
    }
    Ok(token.digest)
}

/// Verifies and then atomically charges one token/use nonce.
///
/// # Errors
///
/// If verification fails, the ledger is unchanged. If replay or budget checks
/// fail, the ledger is unchanged. On success the exact use nonce and budget are
/// consumed before any caller performs the authorized effect.
pub fn verify_and_charge_capability(
    policy: &AcceptedPolicyRoot,
    token: &CapabilityToken,
    trusted_key: &CapabilityTrustedKey,
    request: &CapabilityVerificationRequest,
    ledger: &mut CapabilityLedger,
    use_nonce: CapabilityUseNonce,
) -> Result<CapabilityChargeReceipt, CapabilityError> {
    verify_capability_token(policy, token, trusted_key, request)?;
    ledger.charge(token, use_nonce, request.required_budget)
}

/// Immutable principal-specific grant record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalGrant {
    /// Canonically ordered exact SSMC1 `EffectKind` tags.
    allowed_effect_kind_tags: Vec<u32>,
    /// Canonically ordered exact S20-340 `MutationClass` tags.
    allowed_mutation_class_tags: Vec<u32>,
    /// Canonically ordered allowed reference-adapter identities.
    allowed_adapter_ids: Vec<ReferenceAdapterId>,
    /// Required resource ceilings for this grant.
    resource_ceilings: PolicyResourceCeilings,
}

impl PrincipalGrant {
    /// Constructs an empty grant with zero resource ceilings.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            allowed_effect_kind_tags: Vec::new(),
            allowed_mutation_class_tags: Vec::new(),
            allowed_adapter_ids: Vec::new(),
            resource_ceilings: PolicyResourceCeilings::zero(),
        }
    }

    /// Returns the exact canonically ordered allowed effect-kind tags.
    #[must_use]
    pub fn allowed_effect_kind_tags(&self) -> &[u32] {
        &self.allowed_effect_kind_tags
    }

    /// Returns the exact canonically ordered allowed mutation-class tags.
    #[must_use]
    pub fn allowed_mutation_class_tags(&self) -> &[u32] {
        &self.allowed_mutation_class_tags
    }

    /// Returns the exact canonically ordered adapter allowlist.
    #[must_use]
    pub fn allowed_adapter_ids(&self) -> &[ReferenceAdapterId] {
        &self.allowed_adapter_ids
    }

    /// Returns the exact resource ceilings bound to this grant.
    #[must_use]
    pub const fn resource_ceilings(&self) -> PolicyResourceCeilings {
        self.resource_ceilings
    }
}

/// Builder for one unordered principal grant.
#[derive(Clone, Debug)]
pub struct PrincipalGrantBuilder {
    allowed_effect_kind_tags: Vec<u32>,
    allowed_mutation_class_tags: Vec<u32>,
    allowed_adapter_ids: Vec<ReferenceAdapterId>,
    resource_ceilings: PolicyResourceCeilings,
}

impl PrincipalGrantBuilder {
    /// Creates an empty grant builder with the caller-supplied resource ceilings.
    #[must_use]
    pub fn new(resource_ceilings: PolicyResourceCeilings) -> Self {
        Self {
            allowed_effect_kind_tags: Vec::new(),
            allowed_mutation_class_tags: Vec::new(),
            allowed_adapter_ids: Vec::new(),
            resource_ceilings,
        }
    }

    /// Adds one allowed effect kind by its closed enum value.
    #[must_use]
    pub fn effect_kind(mut self, kind: EffectKind) -> Self {
        self.allowed_effect_kind_tags.push(kind.tag());
        self
    }

    /// Adds one allowed mutation class by its closed enum value.
    #[must_use]
    pub fn mutation_class(mut self, class: MutationClass) -> Self {
        self.allowed_mutation_class_tags
            .push(u32::from(class.tag()));
        self
    }

    /// Adds one allowed reference-adapter identity.
    #[must_use]
    pub fn adapter_id(mut self, adapter_id: ReferenceAdapterId) -> Self {
        self.allowed_adapter_ids.push(adapter_id);
        self
    }

    /// Builds a canonical immutable grant.
    ///
    /// # Errors
    ///
    /// Returns a stable S20-370 error if a collection exceeds policy limits,
    /// duplicates an input, names an unknown tag, or exceeds a resource ceiling.
    pub fn build(mut self) -> Result<PrincipalGrant, PolicyRootError> {
        validate_grant_counts(&self)?;
        self.resource_ceilings
            .validate()
            .map_err(PolicyRootError::PolicyRoot)?;
        reject_unknown_effect_tags(&self.allowed_effect_kind_tags)?;
        reject_unknown_mutation_tags(&self.allowed_mutation_class_tags)?;
        sort_unique(&mut self.allowed_effect_kind_tags)?;
        sort_unique(&mut self.allowed_mutation_class_tags)?;
        sort_unique(&mut self.allowed_adapter_ids)?;
        Ok(PrincipalGrant {
            allowed_effect_kind_tags: self.allowed_effect_kind_tags,
            allowed_mutation_class_tags: self.allowed_mutation_class_tags,
            allowed_adapter_ids: self.allowed_adapter_ids,
            resource_ceilings: self.resource_ceilings,
        })
    }
}

/// Opaque policy-transition mode tag frozen by S20-370.
///
/// External callers can construct only [`Self::EXTERNAL_HIGHER_AUTHORITY_ONLY`].
/// Strict decoding privately preserves unknown tags until semantic validation
/// returns `POLICY_ROOT_TRANSITION_MODE_INVALID`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyTransitionMode(u32);

impl PolicyTransitionMode {
    /// No ordinary-program API may authorize a policy transition.
    pub const EXTERNAL_HIGHER_AUTHORITY_ONLY: Self =
        Self(TRANSITION_MODE_EXTERNAL_HIGHER_AUTHORITY_ONLY);

    /// Returns the exact frozen SCB1 tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        self.0
    }

    const fn from_decoded_tag(tag: u32) -> Self {
        Self(tag)
    }
}

/// Typed eleven-field protected policy-root record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRootRecord {
    /// Exact workspace identifier.
    pub workspace_id: WorkspaceId,
    /// Exact policy-root schema epoch identifier.
    pub schema_epoch_id: SchemaEpochId,
    /// Exact policy schema version. S20-370 v1 accepts only `1`.
    pub policy_schema_version: u32,
    /// Optional parent policy root for lineage evidence only.
    pub parent_policy: Option<PolicyRootId>,
    /// Canonically ordered principal-specific grants.
    pub principal_grants: Vec<(PrincipalId, PrincipalGrant)>,
    /// Canonically ordered protected entity identities.
    pub protected_entities: Vec<EntityId>,
    /// Canonically ordered mandatory `TestCase` identities.
    pub required_tests: Vec<EntityId>,
    /// Canonically ordered mandatory Contract identities.
    pub required_contracts: Vec<EntityId>,
    /// Optional exact expiry value; this crate does not inspect wall-clock time.
    pub expiry_unix_millis: Option<u64>,
    /// Frozen transition mode.
    pub transition_mode: PolicyTransitionMode,
    /// Canonically ordered interpretation flags. Epoch 1 accepts none.
    pub interpretation_flags: Vec<u32>,
}

/// Registry-authorized `PolicyRoot` with its exact stored bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedPolicyRoot {
    /// Derived protected policy-root digest.
    root: PolicyRootId,
    /// Exact standalone bytes including digest trailer.
    stored_bytes: Vec<u8>,
    /// Strictly decoded typed record.
    record: PolicyRootRecord,
}

impl AcceptedPolicyRoot {
    /// Returns the exact protected policy-root digest.
    #[must_use]
    pub const fn root(&self) -> PolicyRootId {
        self.root
    }

    /// Returns the exact registry-authorized standalone bytes.
    #[must_use]
    pub fn stored_bytes(&self) -> &[u8] {
        &self.stored_bytes
    }

    /// Returns the strictly decoded immutable policy record.
    #[must_use]
    pub const fn record(&self) -> &PolicyRootRecord {
        &self.record
    }

    /// Returns the exact grant for one principal.
    ///
    /// # Errors
    ///
    /// Returns `POLICY_GRANT_DENIED` when the principal has no grant in this
    /// accepted policy root.
    pub fn principal_grant(
        &self,
        principal_id: PrincipalId,
    ) -> Result<&PrincipalGrant, PolicyRootError> {
        self.record
            .principal_grants
            .binary_search_by_key(&principal_id, |(id, _)| *id)
            .map(|index| &self.record.principal_grants[index].1)
            .map_err(|_| PolicyRootError::PolicyRoot(PolicyRootErrorCode::GrantDenied))
    }
}

/// Builder for unordered semantic `PolicyRoot` inputs.
#[derive(Clone, Debug)]
pub struct PolicyRootBuilder {
    workspace_id: WorkspaceId,
    parent_policy: Option<PolicyRootId>,
    principal_grants: Vec<(PrincipalId, PrincipalGrant)>,
    protected_entities: Vec<EntityId>,
    required_tests: Vec<EntityId>,
    required_contracts: Vec<EntityId>,
    expiry_unix_millis: Option<u64>,
}

impl PolicyRootBuilder {
    /// Creates a builder from the required workspace binding.
    #[must_use]
    pub const fn new(workspace_id: WorkspaceId) -> Self {
        Self {
            workspace_id,
            parent_policy: None,
            principal_grants: Vec::new(),
            protected_entities: Vec::new(),
            required_tests: Vec::new(),
            required_contracts: Vec::new(),
            expiry_unix_millis: None,
        }
    }

    /// Binds an optional parent policy root for lineage evidence.
    #[must_use]
    pub const fn parent_policy(mut self, parent_policy: PolicyRootId) -> Self {
        self.parent_policy = Some(parent_policy);
        self
    }

    /// Binds an optional literal expiry value.
    #[must_use]
    pub const fn expiry_unix_millis(mut self, expiry_unix_millis: u64) -> Self {
        self.expiry_unix_millis = Some(expiry_unix_millis);
        self
    }

    /// Adds a principal-specific grant.
    #[must_use]
    pub fn principal_grant(mut self, principal_id: PrincipalId, grant: PrincipalGrant) -> Self {
        self.principal_grants.push((principal_id, grant));
        self
    }

    /// Adds one protected entity identity.
    #[must_use]
    pub fn protected_entity(mut self, entity_id: EntityId) -> Self {
        self.protected_entities.push(entity_id);
        self
    }

    /// Adds one mandatory test identity.
    #[must_use]
    pub fn required_test(mut self, entity_id: EntityId) -> Self {
        self.required_tests.push(entity_id);
        self
    }

    /// Adds one mandatory contract identity.
    #[must_use]
    pub fn required_contract(mut self, entity_id: EntityId) -> Self {
        self.required_contracts.push(entity_id);
        self
    }

    /// Builds and authorizes a protected `PolicyRoot` under the exact registered
    /// conformance epoch.
    ///
    /// # Errors
    ///
    /// Returns stable schema, SCB1, or S20-370 policy validation failures.
    pub fn build(
        mut self,
        registry: &SchemaEpochRegistry<PolicyRootEpoch1Decoder>,
    ) -> Result<AcceptedPolicyRoot, PolicyRootError> {
        check_top_level_builder_counts(&self)?;
        sort_grants(&mut self.principal_grants)?;
        sort_unique(&mut self.protected_entities)?;
        sort_unique(&mut self.required_tests)?;
        sort_unique(&mut self.required_contracts)?;
        let epoch_id = conformance_epoch_id()?;
        let record = PolicyRootRecord {
            workspace_id: self.workspace_id,
            schema_epoch_id: epoch_id,
            policy_schema_version: POLICY_SCHEMA_VERSION,
            parent_policy: self.parent_policy,
            principal_grants: self.principal_grants,
            protected_entities: self.protected_entities,
            required_tests: self.required_tests,
            required_contracts: self.required_contracts,
            expiry_unix_millis: self.expiry_unix_millis,
            transition_mode: PolicyTransitionMode::EXTERNAL_HIGHER_AUTHORITY_ONLY,
            interpretation_flags: Vec::new(),
        };
        validate_record_semantics(&record).map_err(PolicyRootError::PolicyRoot)?;
        let payload = encode_payload(&record)?;
        authorize(registry, epoch_id, &payload)?;
        let (stored_bytes, root) = stored_bytes(epoch_id, &payload)?;
        Ok(AcceptedPolicyRoot {
            root,
            stored_bytes,
            record,
        })
    }
}

/// Preserved epoch-1 decoder for the registered `PolicyRoot` conformance epoch.
#[derive(Clone, Debug)]
pub struct PolicyRootEpoch1Decoder {
    epoch_id: SchemaEpochId,
}

impl PolicyRootEpoch1Decoder {
    fn new(epoch_id: SchemaEpochId) -> Self {
        Self { epoch_id }
    }
}

impl EpochDecoder for PolicyRootEpoch1Decoder {
    fn epoch_id(&self) -> SchemaEpochId {
        self.epoch_id
    }

    fn decode_contract(
        &self,
        contract_tag: u32,
        input: &[u8],
    ) -> core::result::Result<(), ScbError> {
        if contract_tag != CONTRACT_TAG {
            return Err(ScbError::new(ScbErrorCode::ContractUnknown));
        }
        let record = decode_payload(input, true)?;
        if record.schema_epoch_id != self.epoch_id {
            return Err(ScbError::new(ScbErrorCode::EpochMismatch));
        }
        Ok(())
    }
}

/// Builds the frozen nonzero conformance epoch registry for `PolicyRoot` v1.
///
/// # Errors
///
/// Returns a stable schema failure if the frozen row no longer validates.
pub fn conformance_registry() -> Result<SchemaEpochRegistry<PolicyRootEpoch1Decoder>, SchemaError> {
    let record = conformance_epoch_record();
    let epoch_id = record.schema_epoch_id()?;
    let entry = RegistryEntry::new(epoch_id, record, PolicyRootEpoch1Decoder::new(epoch_id))?;
    SchemaEpochRegistry::new(vec![entry])
}

/// Returns the frozen nonzero conformance epoch ID.
///
/// # Errors
///
/// Returns a stable schema failure if the frozen row no longer validates.
pub fn conformance_epoch_id() -> Result<SchemaEpochId, SchemaError> {
    conformance_epoch_record().schema_epoch_id()
}

/// Returns the frozen conformance epoch record containing the exact tag-370 descriptor.
#[must_use]
pub fn conformance_epoch_record() -> SchemaEpochRecordV1 {
    SchemaEpochRecordV1 {
        epoch_number: 1,
        scb_format_version: 1,
        hash_algorithm_tag: 1,
        unicode_nfc_version: UnicodeVersion::EPOCH_1,
        limits: EpochLimits::EPOCH_1,
        contracts: vec![expected_descriptor()],
        extensions: Vec::new(),
        predecessor: None,
        migration_contracts: Vec::new(),
    }
}

/// Imports exact stored `PolicyRoot` bytes through the selected preserved decoder.
///
/// # Errors
///
/// Returns stable schema, SCB1, or S20-370 policy validation failures.
pub fn import_policy_root(
    registry: &SchemaEpochRegistry<PolicyRootEpoch1Decoder>,
    input: &[u8],
) -> Result<AcceptedPolicyRoot, PolicyRootError> {
    let (epoch_id, payload, root) = decode_envelope(input)?;
    let record = decode_payload(payload, false)?;
    if record.schema_epoch_id != epoch_id {
        return Err(PolicyRootError::Scb(ScbError::new(
            ScbErrorCode::EpochMismatch,
        )));
    }
    validate_record_semantics(&record).map_err(PolicyRootError::PolicyRoot)?;
    authorize(registry, epoch_id, payload)?;
    Ok(AcceptedPolicyRoot {
        root,
        stored_bytes: input.to_vec(),
        record,
    })
}

/// Pure isolation evidence for an ordinary-program state-root candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyIsolationReport {
    /// Exact accepted policy root that judged the candidate.
    pub policy_root: PolicyRootId,
    /// Exact base state root digest.
    pub base_state_root: sley_id::StateRoot,
    /// Exact candidate state root digest.
    pub candidate_state_root: sley_id::StateRoot,
    /// Count of protected entity bindings checked in deterministic order.
    pub protected_entities_checked: u64,
}

/// Validates that an ordinary-program candidate did not modify the protected
/// policy, schema epoch, contract/test oracles, or protected entity bindings.
///
/// # Errors
///
/// Returns the first deterministic S20-370 isolation failure.
pub fn validate_ordinary_program_isolation(
    policy: &AcceptedPolicyRoot,
    base: &AcceptedStateRoot,
    candidate: &AcceptedStateRoot,
) -> Result<PolicyIsolationReport, PolicyRootError> {
    if policy.root != base.record.policy_root {
        return policy_fail(PolicyRootErrorCode::PolicyRootMismatch);
    }
    if policy.record.workspace_id != base.record.workspace_id
        || base.record.workspace_id != candidate.record.workspace_id
    {
        return policy_fail(PolicyRootErrorCode::WorkspaceMismatch);
    }
    if base.record.policy_root != candidate.record.policy_root {
        return policy_fail(PolicyRootErrorCode::StatePolicyRootChanged);
    }
    if base.record.schema_epoch_id != candidate.record.schema_epoch_id {
        return policy_fail(PolicyRootErrorCode::StateSchemaEpochChanged);
    }
    if base.record.contract_root != candidate.record.contract_root {
        return policy_fail(PolicyRootErrorCode::StateContractRootChanged);
    }
    if base.record.test_root != candidate.record.test_root {
        return policy_fail(PolicyRootErrorCode::StateTestRootChanged);
    }
    for entity_id in &policy.record.protected_entities {
        let base_binding = binding_for(base, *entity_id);
        let candidate_binding = binding_for(candidate, *entity_id);
        if base_binding.is_none() || base_binding != candidate_binding {
            return policy_fail(PolicyRootErrorCode::ProtectedEntityChanged);
        }
    }
    Ok(PolicyIsolationReport {
        policy_root: policy.root,
        base_state_root: base.root,
        candidate_state_root: candidate.root,
        protected_entities_checked: u64::try_from(policy.record.protected_entities.len())
            .map_err(|_| PolicyRootError::PolicyRoot(PolicyRootErrorCode::ResourceLimit))?,
    })
}

/// Finality marker for policy-selected mandatory contract/test plans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyPlanFinality {
    /// Protected policy requirements have been proven present in the validated report.
    PolicyFinal,
}

/// Policy-final mandatory contract/test plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFinalPlan {
    /// Accepted policy root that finalized the plan.
    pub policy_root: PolicyRootId,
    /// Workspace bound by the policy root.
    pub workspace_id: WorkspaceId,
    /// Policy-root schema epoch.
    pub policy_schema_epoch: SchemaEpochId,
    /// Required contracts from the accepted policy.
    pub required_contracts: Vec<EntityId>,
    /// Required tests from the accepted policy.
    pub required_tests: Vec<EntityId>,
    /// Validated contracts from the `ContractTestReport`.
    pub validated_contracts: Vec<EntityId>,
    /// Validated tests from the `ContractTestReport`.
    pub validated_tests: Vec<EntityId>,
    /// Final selected tests from the `ContractTestReport`.
    pub selected_tests: Vec<EntityId>,
    /// Number of typed contract assertions from the validated report.
    pub contract_assertions: u32,
    /// Charged contract/test planning work from the validated report.
    pub contract_test_work: u64,
    /// Distinct policy-final marker.
    pub finality: PolicyPlanFinality,
}

/// Converts one S20-240 `POLICY_INCOMPLETE` report into a policy-final plan
/// after proving mandatory policy IDs were actually validated.
///
/// # Errors
///
/// Returns a deterministic S20-370 finalization failure when the report is
/// forged, noncanonical, not `PolicyIncomplete`, or omits a required ID.
pub fn finalize_mandatory_contract_tests(
    policy: &AcceptedPolicyRoot,
    report: &ContractTestReport,
) -> Result<PolicyFinalPlan, PolicyRootError> {
    validate_report_shape(report)?;
    for required in &policy.record.required_contracts {
        if report.contracts.binary_search(required).is_err() {
            return policy_fail(PolicyRootErrorCode::RequiredContractMissing);
        }
    }
    for required in &policy.record.required_tests {
        if report.tests.binary_search(required).is_err() {
            return policy_fail(PolicyRootErrorCode::RequiredTestMissing);
        }
        if report.selected_tests.binary_search(required).is_err() {
            return policy_fail(PolicyRootErrorCode::RequiredTestNotSelected);
        }
    }
    Ok(PolicyFinalPlan {
        policy_root: policy.root,
        workspace_id: policy.record.workspace_id,
        policy_schema_epoch: policy.record.schema_epoch_id,
        required_contracts: policy.record.required_contracts.clone(),
        required_tests: policy.record.required_tests.clone(),
        validated_contracts: report.contracts.clone(),
        validated_tests: report.tests.clone(),
        selected_tests: report.selected_tests.clone(),
        contract_assertions: report.contract_assertions,
        contract_test_work: report.work,
        finality: PolicyPlanFinality::PolicyFinal,
    })
}

fn finish_capability_token(
    body: CapabilityTokenBody,
    trusted_key: &CapabilityTrustedKey,
) -> Result<CapabilityToken, CapabilityError> {
    let body_bytes = encode_capability_body_record(&body)?;
    let digest = capability_token_digest(&body_bytes)?;
    let authenticator = capability_authenticator(trusted_key.secret(), &body, digest, &body_bytes)?;
    let stored_bytes = encode_capability_token_record(&body, authenticator)?;
    Ok(CapabilityToken {
        body,
        digest,
        authenticator,
        stored_bytes,
    })
}

fn validate_capability_body_shape(body: &CapabilityTokenBody) -> Result<(), CapabilityError> {
    if body.version != CAPABILITY_TOKEN_VERSION {
        return capability_fail(CapabilityErrorCode::VersionUnsupported);
    }
    if !is_known_effect_tag(body.effect_kind_tag) {
        return capability_fail(CapabilityErrorCode::EffectMismatch);
    }
    if body.issued_unix_millis >= body.expiry_unix_millis {
        return capability_fail(CapabilityErrorCode::TimeInvalid);
    }
    body.budget
        .validate_nonzero()
        .map_err(CapabilityError::Capability)
}

fn validate_capability_policy_binding(
    policy: &AcceptedPolicyRoot,
    body: &CapabilityTokenBody,
    now_unix_millis: u64,
) -> Result<(), CapabilityError> {
    if body.policy_root != policy.root() {
        return capability_fail(CapabilityErrorCode::PolicyRootMismatch);
    }
    if body.workspace_id != policy.record.workspace_id {
        return capability_fail(CapabilityErrorCode::WorkspaceMismatch);
    }
    validate_capability_time(policy, body, now_unix_millis)?;
    let grant = policy
        .principal_grant(body.principal_id)
        .map_err(|_| CapabilityError::Capability(CapabilityErrorCode::GrantDenied))?;
    if !grant
        .allowed_effect_kind_tags()
        .contains(&body.effect_kind_tag)
    {
        return capability_fail(CapabilityErrorCode::GrantDenied);
    }
    if !grant.allowed_adapter_ids().contains(&body.adapter_id) {
        return capability_fail(CapabilityErrorCode::GrantDenied);
    }
    if !body.budget.fits_within_ceilings(grant.resource_ceilings()) {
        return capability_fail(CapabilityErrorCode::BudgetExceeded);
    }
    Ok(())
}

fn validate_capability_request_binding(
    policy: &AcceptedPolicyRoot,
    body: &CapabilityTokenBody,
    request: &CapabilityVerificationRequest,
) -> Result<(), CapabilityError> {
    if body.policy_root != policy.root() {
        return capability_fail(CapabilityErrorCode::PolicyRootMismatch);
    }
    if request.workspace_id != policy.record.workspace_id
        || body.workspace_id != request.workspace_id
    {
        return capability_fail(CapabilityErrorCode::WorkspaceMismatch);
    }
    if body.principal_id != request.principal_id {
        return capability_fail(CapabilityErrorCode::PrincipalMismatch);
    }
    if body.state_root != request.state_root {
        return capability_fail(CapabilityErrorCode::StateRootMismatch);
    }
    if body.effect_id != request.effect_id || body.effect_kind_tag != request.effect_kind.tag() {
        return capability_fail(CapabilityErrorCode::EffectMismatch);
    }
    if body.scope_hash != request.scope_hash {
        return capability_fail(CapabilityErrorCode::ScopeMismatch);
    }
    if body.adapter_id != request.adapter_id {
        return capability_fail(CapabilityErrorCode::AdapterMismatch);
    }
    Ok(())
}

fn validate_capability_time(
    policy: &AcceptedPolicyRoot,
    body: &CapabilityTokenBody,
    now_unix_millis: u64,
) -> Result<(), CapabilityError> {
    if now_unix_millis < body.issued_unix_millis {
        return capability_fail(CapabilityErrorCode::TimeInvalid);
    }
    if now_unix_millis >= body.expiry_unix_millis {
        return capability_fail(CapabilityErrorCode::Expired);
    }
    if let Some(policy_expiry) = policy.record.expiry_unix_millis {
        if body.expiry_unix_millis > policy_expiry {
            return capability_fail(CapabilityErrorCode::TimeInvalid);
        }
        if now_unix_millis >= policy_expiry {
            return capability_fail(CapabilityErrorCode::Expired);
        }
    }
    Ok(())
}

fn encode_capability_body_record(body: &CapabilityTokenBody) -> Result<Vec<u8>, ScbError> {
    encode_record(&[
        (1, encode_uvar(u64::from(body.version))),
        (2, body.issuer_id.as_bytes().to_vec()),
        (3, body.key_id.as_bytes().to_vec()),
        (4, body.principal_id.as_bytes().to_vec()),
        (5, body.workspace_id.as_bytes().to_vec()),
        (6, body.state_root.as_bytes().to_vec()),
        (7, body.effect_id.as_bytes().to_vec()),
        (8, encode_uvar(u64::from(body.effect_kind_tag))),
        (9, body.scope_hash.as_bytes().to_vec()),
        (10, body.adapter_id.as_bytes().to_vec()),
        (11, encode_capability_budget(body.budget)?),
        (12, encode_uvar(body.issued_unix_millis)),
        (13, encode_uvar(body.expiry_unix_millis)),
        (14, body.token_nonce.as_bytes().to_vec()),
        (15, body.policy_root.as_bytes().to_vec()),
    ])
}

fn encode_capability_token_record(
    body: &CapabilityTokenBody,
    authenticator: CapabilityAuthenticator,
) -> Result<Vec<u8>, ScbError> {
    encode_record(&[
        (1, encode_uvar(u64::from(body.version))),
        (2, body.issuer_id.as_bytes().to_vec()),
        (3, body.key_id.as_bytes().to_vec()),
        (4, body.principal_id.as_bytes().to_vec()),
        (5, body.workspace_id.as_bytes().to_vec()),
        (6, body.state_root.as_bytes().to_vec()),
        (7, body.effect_id.as_bytes().to_vec()),
        (8, encode_uvar(u64::from(body.effect_kind_tag))),
        (9, body.scope_hash.as_bytes().to_vec()),
        (10, body.adapter_id.as_bytes().to_vec()),
        (11, encode_capability_budget(body.budget)?),
        (12, encode_uvar(body.issued_unix_millis)),
        (13, encode_uvar(body.expiry_unix_millis)),
        (14, body.token_nonce.as_bytes().to_vec()),
        (15, body.policy_root.as_bytes().to_vec()),
        (16, authenticator.as_bytes().to_vec()),
    ])
}

fn encode_capability_budget(budget: CapabilityResourceBudget) -> Result<Vec<u8>, ScbError> {
    encode_record(&[
        (1, encode_uvar(budget.max_fuel)),
        (2, encode_uvar(budget.max_memory_bytes)),
        (3, encode_uvar(budget.max_output_bytes)),
        (4, encode_uvar(budget.max_effect_count)),
        (5, encode_uvar(budget.max_mutation_count)),
        (6, encode_uvar(budget.max_adapter_calls)),
    ])
}

fn decode_capability_token_record(
    input: &[u8],
) -> Result<(CapabilityTokenBody, CapabilityAuthenticator), CapabilityError> {
    let mut record = RecordReader::new(input, CAPABILITY_TOKEN_FIELD_COUNT)?;
    let body = CapabilityTokenBody {
        version: read_complete_u32(record.required(1)?)?,
        issuer_id: CapabilityIssuerId::from_bytes(record.required_array(2)?),
        key_id: CapabilityKeyId::from_bytes(record.required_array(3)?),
        principal_id: PrincipalId::from_bytes(record.required_array(4)?),
        workspace_id: WorkspaceId::from_bytes(record.required_array(5)?),
        state_root: StateRoot::from_bytes(record.required_array(6)?),
        effect_id: EntityId::from_bytes(record.required_array(7)?),
        effect_kind_tag: read_complete_u32(record.required(8)?)?,
        scope_hash: ValueHash::from_bytes(record.required_array(9)?),
        adapter_id: ReferenceAdapterId::from_bytes(record.required_array(10)?),
        budget: decode_capability_budget(record.required(11)?)?,
        issued_unix_millis: read_complete_u64(record.required(12)?)?,
        expiry_unix_millis: read_complete_u64(record.required(13)?)?,
        token_nonce: CapabilityTokenNonce::from_bytes(record.required_array(14)?),
        policy_root: PolicyRootId::from_bytes(record.required_array(15)?),
    };
    let authenticator = CapabilityAuthenticator::from_bytes(record.required_array(16)?);
    record.finish()?;
    Ok((body, authenticator))
}

fn decode_capability_budget(input: &[u8]) -> Result<CapabilityResourceBudget, ScbError> {
    let mut record = RecordReader::new(input, CAPABILITY_BUDGET_FIELD_COUNT)?;
    let budget = CapabilityResourceBudget {
        max_fuel: read_complete_u64(record.required(1)?)?,
        max_memory_bytes: read_complete_u64(record.required(2)?)?,
        max_output_bytes: read_complete_u64(record.required(3)?)?,
        max_effect_count: read_complete_u64(record.required(4)?)?,
        max_mutation_count: read_complete_u64(record.required(5)?)?,
        max_adapter_calls: read_complete_u64(record.required(6)?)?,
    };
    record.finish()?;
    Ok(budget)
}

fn capability_token_digest(body_bytes: &[u8]) -> Result<CapabilityTokenDigest, CapabilityError> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(CAPABILITY_DIGEST_MAGIC);
    preimage.extend_from_slice(&CAPABILITY_TOKEN_VERSION.to_be_bytes());
    preimage.extend_from_slice(
        &u64::try_from(body_bytes.len())
            .map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?
            .to_be_bytes(),
    );
    preimage.extend_from_slice(body_bytes);
    Ok(CapabilityTokenDigest::derive(preimage))
}

fn capability_authenticator(
    secret: CapabilitySecret,
    body: &CapabilityTokenBody,
    digest: CapabilityTokenDigest,
    body_bytes: &[u8],
) -> Result<CapabilityAuthenticator, CapabilityError> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(CAPABILITY_MAC_MAGIC);
    preimage.extend_from_slice(&CAPABILITY_TOKEN_VERSION.to_be_bytes());
    preimage.extend_from_slice(body.issuer_id.as_bytes());
    preimage.extend_from_slice(body.key_id.as_bytes());
    preimage.extend_from_slice(digest.as_bytes());
    preimage.extend_from_slice(
        &u64::try_from(body_bytes.len())
            .map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?
            .to_be_bytes(),
    );
    preimage.extend_from_slice(body_bytes);
    let mut hasher = blake3::Hasher::new_keyed(secret.as_bytes());
    hasher.update(&preimage);
    Ok(CapabilityAuthenticator::from_bytes(
        *hasher.finalize().as_bytes(),
    ))
}

fn constant_time_eq(left: &[u8; ID_LEN], right: &[u8; ID_LEN]) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

fn capability_fail<T>(code: CapabilityErrorCode) -> Result<T, CapabilityError> {
    Err(CapabilityError::Capability(code))
}

fn capability_short_hex(bytes: &[u8; ID_LEN]) -> CapabilityShortHex<'_> {
    CapabilityShortHex(bytes)
}

struct CapabilityShortHex<'a>(&'a [u8; ID_LEN]);

impl fmt::Display for CapabilityShortHex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..4] {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("..")
    }
}

fn expected_descriptor() -> ContractDescriptor {
    ContractDescriptor {
        contract_tag: CONTRACT_TAG,
        digest_domain_tag: DIGEST_DOMAIN_TAG,
        kind_tag: KIND_TAG,
        field_schema_hash: FIELD_SCHEMA_HASH,
        required_fields: (1..=11).collect(),
        optional_fields: Vec::new(),
        variant_tags: Vec::new(),
        decoder_limits_hash: DECODER_LIMITS_HASH,
    }
}

fn authorize(
    registry: &SchemaEpochRegistry<PolicyRootEpoch1Decoder>,
    epoch_id: SchemaEpochId,
    payload: &[u8],
) -> Result<(), PolicyRootError> {
    let descriptor = registry.lookup_contract(epoch_id, CONTRACT_TAG)?;
    if descriptor != &expected_descriptor() {
        return Err(PolicyRootError::Schema(SchemaError::new(
            SchemaErrorCode::ContractUnknown,
        )));
    }
    registry.decode_contract(epoch_id, CONTRACT_TAG, payload)?;
    Ok(())
}

fn encode_payload(record: &PolicyRootRecord) -> Result<Vec<u8>, PolicyRootError> {
    let grants = record
        .principal_grants
        .iter()
        .map(|(principal_id, grant)| {
            Ok((
                principal_id.as_bytes().to_vec(),
                encode_principal_grant(grant)?,
            ))
        })
        .collect::<Result<Vec<_>, PolicyRootError>>()?;
    encode_record(&[
        (1, record.workspace_id.as_bytes().to_vec()),
        (2, record.schema_epoch_id.as_bytes().to_vec()),
        (3, encode_uvar(u64::from(record.policy_schema_version))),
        (4, encode_option_policy_root(record.parent_policy)?),
        (5, encode_map(&grants)?),
        (6, encode_id_set(&record.protected_entities)?),
        (7, encode_id_set(&record.required_tests)?),
        (8, encode_id_set(&record.required_contracts)?),
        (9, encode_option_uvar(record.expiry_unix_millis)?),
        (10, encode_uvar(u64::from(record.transition_mode.tag()))),
        (11, encode_u32_set(&record.interpretation_flags)?),
    ])
    .map_err(Into::into)
}

fn encode_principal_grant(grant: &PrincipalGrant) -> Result<Vec<u8>, PolicyRootError> {
    encode_record(&[
        (1, encode_u32_set(&grant.allowed_effect_kind_tags)?),
        (2, encode_u32_set(&grant.allowed_mutation_class_tags)?),
        (3, encode_id_set(&grant.allowed_adapter_ids)?),
        (4, encode_resource_ceilings(grant.resource_ceilings)?),
    ])
    .map_err(Into::into)
}

fn encode_resource_ceilings(ceilings: PolicyResourceCeilings) -> Result<Vec<u8>, ScbError> {
    encode_record(&[
        (1, encode_uvar(ceilings.max_fuel)),
        (2, encode_uvar(ceilings.max_memory_bytes)),
        (3, encode_uvar(ceilings.max_output_bytes)),
        (4, encode_uvar(ceilings.max_effect_count)),
        (5, encode_uvar(ceilings.max_mutation_count)),
        (6, encode_uvar(ceilings.max_adapter_calls)),
    ])
}

fn encode_option_policy_root(value: Option<PolicyRootId>) -> Result<Vec<u8>, ScbError> {
    match value {
        None => encode_union(0, &[]),
        Some(root) => encode_union(1, root.as_bytes()),
    }
}

fn encode_id_set<T>(values: &[T]) -> Result<Vec<u8>, ScbError>
where
    T: IdBytes,
{
    let elements = values
        .iter()
        .map(|value| value.id_bytes().to_vec())
        .collect::<Vec<_>>();
    encode_list(&elements)
}

fn encode_u32_set(values: &[u32]) -> Result<Vec<u8>, ScbError> {
    let elements = values
        .iter()
        .map(|value| encode_uvar(u64::from(*value)))
        .collect::<Vec<_>>();
    encode_list(&elements)
}

fn stored_bytes(
    epoch_id: SchemaEpochId,
    payload: &[u8],
) -> Result<(Vec<u8>, PolicyRootId), PolicyRootError> {
    let mut preimage = Vec::with_capacity(8 + 10 + 10 + ID_LEN + 10 + payload.len());
    preimage.extend_from_slice(MAGIC);
    preimage.extend_from_slice(&encode_uvar(FORMAT_VERSION));
    preimage.extend_from_slice(&encode_uvar(u64::from(CONTRACT_TAG)));
    preimage.extend_from_slice(epoch_id.as_bytes());
    preimage.extend_from_slice(&encode_uvar(payload.len() as u64));
    preimage.extend_from_slice(payload);
    let root = PolicyRootId::derive(&preimage);
    preimage.extend_from_slice(root.as_bytes());
    if preimage.len() > MAX_STANDALONE_BYTES {
        return Err(PolicyRootError::Scb(ScbError::new(
            ScbErrorCode::ResourceLimit,
        )));
    }
    Ok((preimage, root))
}

fn decode_envelope(input: &[u8]) -> Result<(SchemaEpochId, &[u8], PolicyRootId), PolicyRootError> {
    if input.len() > MAX_STANDALONE_BYTES {
        return Err(PolicyRootError::Scb(ScbError::new(
            ScbErrorCode::ResourceLimit,
        )));
    }
    let mut reader = Reader::new(input);
    if reader.take_exact(MAGIC.len())? != MAGIC {
        return Err(PolicyRootError::Scb(ScbError::new(
            ScbErrorCode::MagicInvalid,
        )));
    }
    if reader.read_uvar_width(64)? != FORMAT_VERSION {
        return Err(PolicyRootError::Scb(ScbError::new(
            ScbErrorCode::VersionUnsupported,
        )));
    }
    if reader.read_uvar_width(32)? != u64::from(CONTRACT_TAG) {
        return Err(PolicyRootError::Scb(ScbError::new(
            ScbErrorCode::ContractUnknown,
        )));
    }
    let epoch_id = SchemaEpochId::from_bytes(reader.take_array()?);
    let payload_len = reader.read_len(MAX_STANDALONE_BYTES)?;
    let payload = reader.take_exact(payload_len)?;
    let digest = reader.take_exact(ID_LEN)?;
    if !reader.is_finished() {
        return Err(PolicyRootError::Scb(ScbError::new(
            ScbErrorCode::TrailingBytes,
        )));
    }
    let root = PolicyRootId::derive(&input[..input.len() - ID_LEN]);
    if digest != root.as_bytes() {
        return Err(PolicyRootError::Scb(ScbError::new(
            ScbErrorCode::DigestMismatch,
        )));
    }
    Ok((epoch_id, payload, root))
}

fn decode_payload(input: &[u8], enforce_semantics: bool) -> Result<PolicyRootRecord, ScbError> {
    let mut record = RecordReader::new(input, FIELD_COUNT)?;
    let transition_tag = read_complete_u32(record.required(10)?)?;
    let out = PolicyRootRecord {
        workspace_id: WorkspaceId::from_bytes(record.required_array(1)?),
        schema_epoch_id: SchemaEpochId::from_bytes(record.required_array(2)?),
        policy_schema_version: read_complete_u32(record.required(3)?)?,
        parent_policy: decode_option_policy_root(record.required(4)?)?,
        principal_grants: decode_principal_grants(record.required(5)?)?,
        protected_entities: decode_entity_set(record.required(6)?)?,
        required_tests: decode_entity_set(record.required(7)?)?,
        required_contracts: decode_entity_set(record.required(8)?)?,
        expiry_unix_millis: decode_option_u64(record.required(9)?)?,
        transition_mode: PolicyTransitionMode::from_decoded_tag(transition_tag),
        interpretation_flags: decode_u32_set_payload(record.required(11)?)?,
    };
    record.finish()?;
    if enforce_semantics {
        validate_record_semantics(&out).map_err(policy_code_as_scb)?;
    }
    Ok(out)
}

fn decode_principal_grants(input: &[u8]) -> Result<Vec<(PrincipalId, PrincipalGrant)>, ScbError> {
    let mut reader = Reader::new(input);
    let count = reader.read_count()?;
    let count = usize::try_from(count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if count > MAX_POLICY_PRINCIPAL_GRANTS || count > reader.remaining() / (ID_LEN + 2) {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let mut previous: Option<[u8; ID_LEN]> = None;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let key = exact_array(reader.read_sized(MAX_STANDALONE_BYTES)?)?;
        if previous.is_some_and(|prev| prev > key) {
            return Err(ScbError::new(ScbErrorCode::MapOrder));
        }
        if previous == Some(key) {
            return Err(ScbError::new(ScbErrorCode::MapDuplicate));
        }
        let grant = decode_principal_grant(reader.read_sized(MAX_STANDALONE_BYTES)?)?;
        out.push((PrincipalId::from_bytes(key), grant));
        previous = Some(key);
    }
    if reader.is_finished() {
        Ok(out)
    } else {
        Err(ScbError::new(ScbErrorCode::TrailingBytes))
    }
}

fn decode_principal_grant(input: &[u8]) -> Result<PrincipalGrant, ScbError> {
    let mut record = RecordReader::new(input, GRANT_FIELD_COUNT)?;
    let grant = PrincipalGrant {
        allowed_effect_kind_tags: decode_u32_set_payload(record.required(1)?)?,
        allowed_mutation_class_tags: decode_u32_set_payload(record.required(2)?)?,
        allowed_adapter_ids: decode_adapter_set(record.required(3)?)?,
        resource_ceilings: decode_resource_ceilings(record.required(4)?)?,
    };
    record.finish()?;
    Ok(grant)
}

fn decode_resource_ceilings(input: &[u8]) -> Result<PolicyResourceCeilings, ScbError> {
    let mut record = RecordReader::new(input, RESOURCE_FIELD_COUNT)?;
    let ceilings = PolicyResourceCeilings {
        max_fuel: read_complete_u64(record.required(1)?)?,
        max_memory_bytes: read_complete_u64(record.required(2)?)?,
        max_output_bytes: read_complete_u64(record.required(3)?)?,
        max_effect_count: read_complete_u64(record.required(4)?)?,
        max_mutation_count: read_complete_u64(record.required(5)?)?,
        max_adapter_calls: read_complete_u64(record.required(6)?)?,
    };
    record.finish()?;
    Ok(ceilings)
}

fn decode_option_policy_root(input: &[u8]) -> Result<Option<PolicyRootId>, ScbError> {
    let (tag, payload) = decode_union_parts(input)?;
    match tag {
        0 if payload.is_empty() => Ok(None),
        1 => Ok(Some(PolicyRootId::from_bytes(exact_array(payload)?))),
        _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
    }
}

fn decode_option_u64(input: &[u8]) -> Result<Option<u64>, ScbError> {
    let (tag, payload) = decode_union_parts(input)?;
    match tag {
        0 if payload.is_empty() => Ok(None),
        1 => Ok(Some(read_complete_u64(payload)?)),
        _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
    }
}

fn decode_union_parts(input: &[u8]) -> Result<(u64, &[u8]), ScbError> {
    let mut reader = Reader::new(input);
    let tag = reader.read_uvar_width(32)?;
    let len = reader.read_len(MAX_STANDALONE_BYTES)?;
    let payload = reader.take_exact(len)?;
    if reader.is_finished() {
        Ok((tag, payload))
    } else {
        Err(ScbError::new(ScbErrorCode::TrailingBytes))
    }
}

fn decode_entity_set(input: &[u8]) -> Result<Vec<EntityId>, ScbError> {
    decode_fixed_set(input).map(|values| values.into_iter().map(EntityId::from_bytes).collect())
}

fn decode_adapter_set(input: &[u8]) -> Result<Vec<ReferenceAdapterId>, ScbError> {
    decode_fixed_set(input).map(|values| {
        values
            .into_iter()
            .map(ReferenceAdapterId::from_bytes)
            .collect()
    })
}

fn decode_fixed_set(input: &[u8]) -> Result<Vec<[u8; ID_LEN]>, ScbError> {
    let mut reader = Reader::new(input);
    let count = reader.read_count()?;
    let count = usize::try_from(count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if count > reader.remaining() / (ID_LEN + 1) {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let mut previous: Option<[u8; ID_LEN]> = None;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let value = exact_array(reader.read_sized(MAX_STANDALONE_BYTES)?)?;
        if previous.is_some_and(|prev| prev >= value) {
            return Err(if previous == Some(value) {
                ScbError::new(ScbErrorCode::MapDuplicate)
            } else {
                ScbError::new(ScbErrorCode::MapOrder)
            });
        }
        previous = Some(value);
        out.push(value);
    }
    if reader.is_finished() {
        Ok(out)
    } else {
        Err(ScbError::new(ScbErrorCode::TrailingBytes))
    }
}

fn decode_u32_set_payload(input: &[u8]) -> Result<Vec<u32>, ScbError> {
    let mut reader = Reader::new(input);
    let count = reader.read_count()?;
    let count = usize::try_from(count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if count > reader.remaining() {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let mut previous: Option<Vec<u8>> = None;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let element = reader.read_sized(MAX_STANDALONE_BYTES)?;
        if previous.as_deref().is_some_and(|prev| prev >= element) {
            return Err(if previous.as_deref() == Some(element) {
                ScbError::new(ScbErrorCode::MapDuplicate)
            } else {
                ScbError::new(ScbErrorCode::MapOrder)
            });
        }
        out.push(read_complete_u32(element)?);
        previous = Some(element.to_vec());
    }
    if reader.is_finished() {
        Ok(out)
    } else {
        Err(ScbError::new(ScbErrorCode::TrailingBytes))
    }
}

fn read_complete_u32(input: &[u8]) -> Result<u32, ScbError> {
    let mut reader = Reader::new(input);
    let value = reader.read_uvar_width(32)?;
    if !reader.is_finished() {
        return Err(ScbError::new(ScbErrorCode::TrailingBytes));
    }
    u32::try_from(value).map_err(|_| ScbError::new(ScbErrorCode::IntegerOverflow))
}

fn read_complete_u64(input: &[u8]) -> Result<u64, ScbError> {
    let mut reader = Reader::new(input);
    let value = reader.read_uvar_width(64)?;
    if reader.is_finished() {
        Ok(value)
    } else {
        Err(ScbError::new(ScbErrorCode::TrailingBytes))
    }
}

fn validate_record_semantics(record: &PolicyRootRecord) -> Result<(), PolicyRootErrorCode> {
    if record.policy_schema_version != POLICY_SCHEMA_VERSION {
        return Err(PolicyRootErrorCode::VersionUnsupported);
    }
    if record.transition_mode.tag() != TRANSITION_MODE_EXTERNAL_HIGHER_AUTHORITY_ONLY {
        return Err(PolicyRootErrorCode::TransitionModeInvalid);
    }
    if !record.interpretation_flags.is_empty() {
        return Err(PolicyRootErrorCode::FlagUnknown);
    }
    if record.principal_grants.len() > MAX_POLICY_PRINCIPAL_GRANTS
        || record.protected_entities.len() > MAX_POLICY_PROTECTED_ENTITIES
        || record.required_tests.len() > MAX_POLICY_REQUIRED_TESTS
        || record.required_contracts.len() > MAX_POLICY_REQUIRED_CONTRACTS
    {
        return Err(PolicyRootErrorCode::ResourceLimit);
    }
    for (_, grant) in &record.principal_grants {
        validate_grant(grant)?;
    }
    Ok(())
}

fn validate_grant(grant: &PrincipalGrant) -> Result<(), PolicyRootErrorCode> {
    if grant.allowed_effect_kind_tags.len() > MAX_POLICY_GRANT_TAGS
        || grant.allowed_mutation_class_tags.len() > MAX_POLICY_GRANT_TAGS
        || grant.allowed_adapter_ids.len() > MAX_POLICY_GRANT_ADAPTERS
    {
        return Err(PolicyRootErrorCode::ResourceLimit);
    }
    grant.resource_ceilings.validate()?;
    if grant
        .allowed_effect_kind_tags
        .iter()
        .any(|tag| !is_known_effect_tag(*tag))
    {
        return Err(PolicyRootErrorCode::EffectKindUnknown);
    }
    if grant
        .allowed_mutation_class_tags
        .iter()
        .any(|tag| !is_known_mutation_tag(*tag))
    {
        return Err(PolicyRootErrorCode::MutationClassUnknown);
    }
    Ok(())
}

fn policy_code_as_scb(code: PolicyRootErrorCode) -> ScbError {
    match code {
        PolicyRootErrorCode::VersionUnsupported
        | PolicyRootErrorCode::EffectKindUnknown
        | PolicyRootErrorCode::MutationClassUnknown
        | PolicyRootErrorCode::TransitionModeInvalid
        | PolicyRootErrorCode::FlagUnknown => ScbError::new(ScbErrorCode::FieldUnknown),
        PolicyRootErrorCode::ResourceLimit => ScbError::new(ScbErrorCode::ResourceLimit),
        _ => ScbError::new(ScbErrorCode::FieldDuplicate),
    }
}

fn validate_grant_counts(grant: &PrincipalGrantBuilder) -> Result<(), PolicyRootError> {
    if grant.allowed_effect_kind_tags.len() > MAX_POLICY_GRANT_TAGS
        || grant.allowed_mutation_class_tags.len() > MAX_POLICY_GRANT_TAGS
        || grant.allowed_adapter_ids.len() > MAX_POLICY_GRANT_ADAPTERS
    {
        policy_fail(PolicyRootErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn check_top_level_builder_counts(builder: &PolicyRootBuilder) -> Result<(), PolicyRootError> {
    if builder.principal_grants.len() > MAX_POLICY_PRINCIPAL_GRANTS
        || builder.protected_entities.len() > MAX_POLICY_PROTECTED_ENTITIES
        || builder.required_tests.len() > MAX_POLICY_REQUIRED_TESTS
        || builder.required_contracts.len() > MAX_POLICY_REQUIRED_CONTRACTS
        || u64::try_from(builder.principal_grants.len())
            .map_or(true, |count| count > MAX_COLLECTION_ELEMENTS)
        || u64::try_from(builder.protected_entities.len())
            .map_or(true, |count| count > MAX_COLLECTION_ELEMENTS)
        || u64::try_from(builder.required_tests.len())
            .map_or(true, |count| count > MAX_COLLECTION_ELEMENTS)
        || u64::try_from(builder.required_contracts.len())
            .map_or(true, |count| count > MAX_COLLECTION_ELEMENTS)
    {
        policy_fail(PolicyRootErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn reject_unknown_effect_tags(tags: &[u32]) -> Result<(), PolicyRootError> {
    if tags.iter().all(|tag| is_known_effect_tag(*tag)) {
        Ok(())
    } else {
        policy_fail(PolicyRootErrorCode::EffectKindUnknown)
    }
}

fn reject_unknown_mutation_tags(tags: &[u32]) -> Result<(), PolicyRootError> {
    if tags.iter().all(|tag| is_known_mutation_tag(*tag)) {
        Ok(())
    } else {
        policy_fail(PolicyRootErrorCode::MutationClassUnknown)
    }
}

const fn is_known_effect_tag(tag: u32) -> bool {
    tag >= 1 && tag <= 8
}

const fn is_known_mutation_tag(tag: u32) -> bool {
    tag >= 1 && tag <= 16
}

fn sort_grants(grants: &mut [(PrincipalId, PrincipalGrant)]) -> Result<(), PolicyRootError> {
    grants.sort_by_key(|(principal_id, _)| *principal_id);
    if grants.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        policy_fail(PolicyRootErrorCode::DuplicateInput)
    } else {
        Ok(())
    }
}

fn sort_unique<T: Ord>(values: &mut [T]) -> Result<(), PolicyRootError> {
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        policy_fail(PolicyRootErrorCode::DuplicateInput)
    } else {
        Ok(())
    }
}

fn exact_array(input: &[u8]) -> Result<[u8; ID_LEN], ScbError> {
    input
        .try_into()
        .map_err(|_| ScbError::new(ScbErrorCode::LengthOverflow))
}

fn binding_for(root: &AcceptedStateRoot, entity_id: EntityId) -> Option<sley_id::ObjectId> {
    root.record
        .entity_bindings
        .binary_search_by_key(&entity_id, |(id, _)| *id)
        .ok()
        .map(|position| root.record.entity_bindings[position].1)
}

fn validate_report_shape(report: &ContractTestReport) -> Result<(), PolicyRootError> {
    if !matches!(
        report.selection_finality,
        TestPlanFinality::PolicyIncomplete
    ) || !strict_ids(&report.contracts)
        || !strict_ids(&report.tests)
        || !strict_ids(&report.selected_tests)
        || report.contracts.len() > MAX_POLICY_REQUIRED_CONTRACTS
        || report.tests.len() > MAX_POLICY_REQUIRED_TESTS
        || report.selected_tests.len() > MAX_POLICY_REQUIRED_TESTS
        || !report
            .selected_tests
            .iter()
            .all(|test| report.tests.binary_search(test).is_ok())
    {
        policy_fail(PolicyRootErrorCode::FinalReportInvalid)
    } else {
        Ok(())
    }
}

fn strict_ids(values: &[EntityId]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn policy_fail<T>(code: PolicyRootErrorCode) -> Result<T, PolicyRootError> {
    Err(PolicyRootError::PolicyRoot(code))
}

trait IdBytes {
    fn id_bytes(&self) -> &[u8; ID_LEN];
}

impl IdBytes for EntityId {
    fn id_bytes(&self) -> &[u8; ID_LEN] {
        self.as_bytes()
    }
}

impl IdBytes for ReferenceAdapterId {
    fn id_bytes(&self) -> &[u8; ID_LEN] {
        self.as_bytes()
    }
}

#[derive(Clone)]
struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    const fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }

    const fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    fn take_exact(&mut self, len: usize) -> Result<&'a [u8], ScbError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| ScbError::new(ScbErrorCode::LengthOverflow))?;
        if end > self.input.len() {
            return Err(ScbError::new(ScbErrorCode::LengthOverflow));
        }
        let slice = &self.input[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ScbError> {
        let mut out = [0_u8; N];
        out.copy_from_slice(self.take_exact(N)?);
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, ScbError> {
        self.take_exact(1)?
            .first()
            .copied()
            .ok_or_else(|| ScbError::new(ScbErrorCode::LengthOverflow))
    }

    fn read_uvar_width(&mut self, width: u8) -> Result<u64, ScbError> {
        let mut value = 0_u64;
        let mut shift = 0_u32;
        let mut bytes_read = 0_u8;
        loop {
            let byte = self.read_u8()?;
            bytes_read += 1;
            let payload = u64::from(byte & 0x7f);
            if shift >= 64 && payload != 0 {
                return Err(ScbError::new(ScbErrorCode::IntegerOverflow));
            }
            if shift < 64 {
                if shift == 63 && payload > 1 {
                    return Err(ScbError::new(ScbErrorCode::IntegerOverflow));
                }
                value |= payload
                    .checked_shl(shift)
                    .ok_or_else(|| ScbError::new(ScbErrorCode::IntegerOverflow))?;
            }
            if byte & 0x80 == 0 {
                if bytes_read > 1 && payload == 0 {
                    return Err(ScbError::new(ScbErrorCode::VarintNonMinimal));
                }
                if width < 64 && value >= (1_u64 << width) {
                    return Err(ScbError::new(ScbErrorCode::IntegerOverflow));
                }
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 + 7 {
                return Err(ScbError::new(ScbErrorCode::IntegerOverflow));
            }
        }
    }

    fn read_len(&mut self, max: usize) -> Result<usize, ScbError> {
        let len = self.read_uvar_width(64)?;
        let len = usize::try_from(len).map_err(|_| ScbError::new(ScbErrorCode::LengthOverflow))?;
        if len > max {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        Ok(len)
    }

    fn read_sized(&mut self, max: usize) -> Result<&'a [u8], ScbError> {
        let len = self.read_len(max)?;
        self.take_exact(len)
    }

    fn read_count(&mut self) -> Result<u64, ScbError> {
        let count = self.read_uvar_width(64)?;
        if count > MAX_COLLECTION_ELEMENTS {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        Ok(count)
    }

    fn read_record_field_count(&mut self) -> Result<u64, ScbError> {
        let count = self.read_uvar_width(64)?;
        if count > MAX_RECORD_FIELDS {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        Ok(count)
    }
}

struct RecordReader<'a> {
    fields: Vec<(u32, &'a [u8])>,
}

impl<'a> RecordReader<'a> {
    fn new(input: &'a [u8], expected_fields: u64) -> Result<Self, ScbError> {
        let mut reader = Reader::new(input);
        let field_count = reader.read_record_field_count()?;
        if field_count < expected_fields {
            return Err(ScbError::new(ScbErrorCode::FieldMissing));
        }
        let count =
            usize::try_from(field_count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
        if count > reader.remaining() / 2 {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        let mut fields = Vec::with_capacity(count);
        let mut previous_tag = None;
        for _ in 0..count {
            let tag = reader.read_uvar_width(32)?;
            let tag =
                u32::try_from(tag).map_err(|_| ScbError::new(ScbErrorCode::IntegerOverflow))?;
            if previous_tag.is_some_and(|previous| previous == tag) {
                return Err(ScbError::new(ScbErrorCode::FieldDuplicate));
            }
            if previous_tag.is_some_and(|previous| previous > tag) {
                return Err(ScbError::new(ScbErrorCode::FieldOrder));
            }
            let value = reader.read_sized(MAX_STANDALONE_BYTES)?;
            fields.push((tag, value));
            previous_tag = Some(tag);
        }
        if !reader.is_finished() {
            return Err(ScbError::new(ScbErrorCode::TrailingBytes));
        }
        Ok(Self { fields })
    }

    fn required(&mut self, tag: u32) -> Result<&'a [u8], ScbError> {
        self.fields
            .binary_search_by_key(&tag, |(field_tag, _)| *field_tag)
            .map(|index| self.fields.remove(index).1)
            .map_err(|_| ScbError::new(ScbErrorCode::FieldMissing))
    }

    fn required_array<const N: usize>(&mut self, tag: u32) -> Result<[u8; N], ScbError> {
        self.required(tag)?
            .try_into()
            .map_err(|_| ScbError::new(ScbErrorCode::LengthOverflow))
    }

    fn finish(self) -> Result<(), ScbError> {
        if self.fields.is_empty() {
            Ok(())
        } else {
            Err(ScbError::new(ScbErrorCode::FieldUnknown))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;
    use sley_check::contracts::TestPlanFinality;
    use sley_id::{ObjectId, StateRoot};
    use sley_state_root::{StateRootBuilder, conformance_registry as state_root_registry};

    fn id(byte: u8) -> [u8; ID_LEN] {
        [byte; ID_LEN]
    }

    fn workspace(byte: u8) -> WorkspaceId {
        WorkspaceId::from_bytes(id(byte))
    }

    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::from_bytes(id(byte))
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes(id(byte))
    }

    fn object(byte: u8) -> ObjectId {
        ObjectId::from_bytes(id(byte))
    }

    fn root(byte: u8) -> StateRoot {
        StateRoot::from_bytes(id(byte))
    }

    fn policy_root(byte: u8) -> PolicyRootId {
        PolicyRootId::from_bytes(id(byte))
    }

    fn adapter(byte: u8) -> ReferenceAdapterId {
        ReferenceAdapterId::from_bytes(id(byte))
    }

    fn registry() -> SchemaEpochRegistry<PolicyRootEpoch1Decoder> {
        conformance_registry().unwrap()
    }

    fn grant() -> PrincipalGrant {
        PrincipalGrantBuilder::new(PolicyResourceCeilings::new(100, 200, 300, 4, 5, 6))
            .adapter_id(adapter(33))
            .mutation_class(MutationClass::ReplaceEntityVersion)
            .mutation_class(MutationClass::CreateEntity)
            .effect_kind(EffectKind::FileRead)
            .effect_kind(EffectKind::StdoutWrite)
            .build()
            .unwrap()
    }

    fn builder() -> PolicyRootBuilder {
        PolicyRootBuilder::new(workspace(1))
            .parent_policy(policy_root(8))
            .expiry_unix_millis(999)
            .principal_grant(principal(3), grant())
            .principal_grant(principal(2), PrincipalGrant::empty())
            .protected_entity(entity(40))
            .protected_entity(entity(39))
            .required_test(entity(51))
            .required_test(entity(50))
            .required_contract(entity(61))
            .required_contract(entity(60))
    }

    fn accepted_policy() -> AcceptedPolicyRoot {
        builder().build(&registry()).unwrap()
    }

    fn state_with(
        policy: PolicyRootId,
        schema_marker: u8,
        contract_marker: u8,
        test_marker: u8,
        protected_object: u8,
    ) -> AcceptedStateRoot {
        let mut accepted = StateRootBuilder::new(
            workspace(1),
            object(contract_marker),
            object(test_marker),
            policy,
        )
        .entity_binding(entity(39), object(protected_object))
        .entity_binding(entity(40), object(protected_object + 1))
        .entity_binding(entity(70), object(70))
        .entry_point(entity(70))
        .dependency_root(root(81))
        .build(&state_root_registry().unwrap())
        .unwrap();
        if schema_marker != 0 {
            accepted.record.schema_epoch_id = SchemaEpochId::from_bytes(id(schema_marker));
        }
        accepted
    }

    fn report() -> ContractTestReport {
        ContractTestReport {
            contracts: vec![entity(60), entity(61), entity(62)],
            tests: vec![entity(50), entity(51), entity(52)],
            selected_tests: vec![entity(50), entity(51)],
            selection_finality: TestPlanFinality::PolicyIncomplete,
            contract_assertions: 2,
            work: 77,
        }
    }

    fn cap_trusted_key() -> CapabilityTrustedKey {
        CapabilityTrustedKey::new(
            CapabilityIssuerId::from_bytes(id(10)),
            CapabilityKeyId::from_bytes(id(11)),
            CapabilitySecret::from_bytes(id(12)),
        )
    }

    fn cap_budget() -> CapabilityResourceBudget {
        CapabilityResourceBudget::new(1, 2, 3, 2, 0, 2)
    }

    fn cap_request() -> CapabilityTokenRequest {
        CapabilityTokenRequest {
            principal_id: principal(3),
            workspace_id: workspace(1),
            state_root: root(7),
            effect_id: entity(80),
            effect_kind: EffectKind::FileRead,
            scope_hash: ValueHash::from_bytes(id(90)),
            adapter_id: adapter(33),
            budget: cap_budget(),
            now_unix_millis: 100,
            expiry_unix_millis: 200,
            token_nonce: CapabilityTokenNonce::from_bytes(id(13)),
        }
    }

    fn cap_verification_request() -> CapabilityVerificationRequest {
        CapabilityVerificationRequest {
            principal_id: principal(3),
            workspace_id: workspace(1),
            state_root: root(7),
            effect_id: entity(80),
            effect_kind: EffectKind::FileRead,
            scope_hash: ValueHash::from_bytes(id(90)),
            adapter_id: adapter(33),
            now_unix_millis: 150,
            required_budget: CapabilityResourceBudget::adapter_invocation(),
        }
    }

    fn issued_token() -> (AcceptedPolicyRoot, CapabilityTrustedKey, CapabilityToken) {
        let policy = accepted_policy();
        let trusted_key = cap_trusted_key();
        let token = issue_capability_token(&policy, &trusted_key, &cap_request()).unwrap();
        (policy, trusted_key, token)
    }

    fn hex(bytes: impl AsRef<[u8]>) -> String {
        let mut out = String::new();
        for byte in bytes.as_ref() {
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out
    }

    fn from_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| u8::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn descriptor_hash_preimages_are_frozen() {
        assert_eq!(
            FIELD_SCHEMA_HASH,
            *blake3::hash(FIELD_SCHEMA_PREIMAGE.as_bytes()).as_bytes()
        );
        assert_eq!(
            DECODER_LIMITS_HASH,
            *blake3::hash(DECODER_LIMITS_PREIMAGE.as_bytes()).as_bytes()
        );
    }

    #[test]
    fn descriptor_and_registered_epoch_are_exact() {
        let record = conformance_epoch_record();
        let descriptor = record.contracts.single().unwrap();
        assert_eq!(descriptor.contract_tag, 370);
        assert_eq!(descriptor.digest_domain_tag, 8);
        assert_eq!(descriptor.kind_tag, 370);
        assert_eq!(
            descriptor.required_fields,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        );
        assert!(descriptor.optional_fields.is_empty());
        assert!(descriptor.variant_tags.is_empty());
        assert_ne!(conformance_epoch_id().unwrap().as_bytes(), &[0; ID_LEN]);
    }

    #[test]
    fn accepted_vector_is_frozen_and_round_trips() {
        let accepted = accepted_policy();
        assert_eq!(
            hex(accepted.root.as_bytes()),
            "7a933b888107588fd4cb942581e531f632a52dd15bb342145337b5ceac2907bf"
        );
        assert_eq!(
            hex(&accepted.stored_bytes),
            "534c45595343423101f2026bfec771c335f6b1ff85407eb8b630b9eced0ce065723b862830924ed299d644f8030b0120010101010101010101010101010101010101010101010101010101010101010102206bfec771c335f6b1ff85407eb8b630b9eced0ce065723b862830924ed299d64403010104220120080808080808080808080808080808080808080808080808080808080808080805ae01022002020202020202020202020202020202020202020202020202020202020202021f040101000201000301000413060101000201000301000401000501000601002003030303030303030303030303030303030303030303030303030303030303034a0401050201010103020502010101020322012021212121212121212121212121212121212121212121212121212121212121210415060101640202c8010302ac02040104050105060106064302202727272727272727272727272727272727272727272727272727272727272727202828282828282828282828282828282828282828282828282828282828282828074302203232323232323232323232323232323232323232323232323232323232323232203333333333333333333333333333333333333333333333333333333333333333084302203c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c203d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d09040102e7070a01010b01007a933b888107588fd4cb942581e531f632a52dd15bb342145337b5ceac2907bf"
        );
        assert_eq!(
            import_policy_root(&registry(), &accepted.stored_bytes).unwrap(),
            accepted
        );
    }

    #[test]
    fn synthetic_zero_epoch_hashes_but_authorization_rejects() {
        let zero_epoch = SchemaEpochId::from_bytes([0; ID_LEN]);
        let record = PolicyRootRecord {
            workspace_id: workspace(0),
            schema_epoch_id: zero_epoch,
            policy_schema_version: 1,
            parent_policy: None,
            principal_grants: Vec::new(),
            protected_entities: Vec::new(),
            required_tests: Vec::new(),
            required_contracts: Vec::new(),
            expiry_unix_millis: None,
            transition_mode: PolicyTransitionMode::EXTERNAL_HIGHER_AUTHORITY_ONLY,
            interpretation_flags: Vec::new(),
        };
        let payload = encode_payload(&record).unwrap();
        assert_eq!(payload.len(), 98);
        let (stored, root) = stored_bytes(zero_epoch, &payload).unwrap();
        assert_eq!(stored.len() - ID_LEN, 142);
        assert_eq!(
            hex(root.as_bytes()),
            "94d3887012304f42f581dac7516a3c3998b83210edf7cbdc8d31377fbde92ad4"
        );

        let error = import_policy_root(&registry(), &stored).unwrap_err();
        assert_eq!(error.code_str(), "SCHEMA_EPOCH_MISMATCH");
    }

    #[test]
    fn unordered_inputs_have_identical_root_for_128_repeats() {
        let expected = accepted_policy();
        for _ in 0..128 {
            let shuffled = PolicyRootBuilder::new(workspace(1))
                .required_contract(entity(60))
                .required_test(entity(50))
                .protected_entity(entity(39))
                .principal_grant(principal(2), PrincipalGrant::empty())
                .principal_grant(principal(3), grant())
                .required_contract(entity(61))
                .protected_entity(entity(40))
                .expiry_unix_millis(999)
                .required_test(entity(51))
                .parent_policy(policy_root(8))
                .build(&registry())
                .unwrap();
            assert_eq!(expected.root, shuffled.root);
            assert_eq!(expected.stored_bytes, shuffled.stored_bytes);
        }
    }

    #[test]
    fn every_policy_field_perturbation_changes_root() {
        let base = accepted_policy().root;
        let variants = [
            PolicyRootBuilder::new(workspace(9))
                .principal_grant(principal(2), PrincipalGrant::empty())
                .build(&registry())
                .unwrap()
                .root,
            PolicyRootBuilder::new(workspace(1))
                .parent_policy(policy_root(9))
                .principal_grant(principal(2), PrincipalGrant::empty())
                .build(&registry())
                .unwrap()
                .root,
            PolicyRootBuilder::new(workspace(1))
                .principal_grant(principal(4), PrincipalGrant::empty())
                .build(&registry())
                .unwrap()
                .root,
            PolicyRootBuilder::new(workspace(1))
                .principal_grant(principal(2), PrincipalGrant::empty())
                .protected_entity(entity(41))
                .build(&registry())
                .unwrap()
                .root,
            PolicyRootBuilder::new(workspace(1))
                .principal_grant(principal(2), PrincipalGrant::empty())
                .required_test(entity(52))
                .build(&registry())
                .unwrap()
                .root,
            PolicyRootBuilder::new(workspace(1))
                .principal_grant(principal(2), PrincipalGrant::empty())
                .required_contract(entity(62))
                .build(&registry())
                .unwrap()
                .root,
            PolicyRootBuilder::new(workspace(1))
                .principal_grant(principal(2), PrincipalGrant::empty())
                .expiry_unix_millis(1)
                .build(&registry())
                .unwrap()
                .root,
        ];
        for variant in variants {
            assert_ne!(base, variant);
        }
    }

    #[test]
    fn builder_rejects_duplicate_principals_sets_and_grant_tags() {
        assert_eq!(
            builder()
                .principal_grant(principal(2), PrincipalGrant::empty())
                .build(&registry())
                .unwrap_err()
                .code_str(),
            "POLICY_ROOT_DUPLICATE_INPUT"
        );
        assert_eq!(
            builder()
                .protected_entity(entity(39))
                .build(&registry())
                .unwrap_err()
                .code_str(),
            "POLICY_ROOT_DUPLICATE_INPUT"
        );
        assert_eq!(
            PrincipalGrantBuilder::new(PolicyResourceCeilings::zero())
                .effect_kind(EffectKind::FileRead)
                .effect_kind(EffectKind::FileRead)
                .build()
                .unwrap_err()
                .code_str(),
            "POLICY_ROOT_DUPLICATE_INPUT"
        );
    }

    #[test]
    fn grant_denial_and_empty_grants_do_not_imply_authority() {
        let accepted = accepted_policy();
        assert_eq!(
            accepted
                .principal_grant(principal(99))
                .unwrap_err()
                .code_str(),
            "POLICY_GRANT_DENIED"
        );
        let empty = accepted.principal_grant(principal(2)).unwrap();
        assert!(empty.allowed_effect_kind_tags.is_empty());
        assert!(empty.allowed_mutation_class_tags.is_empty());
        assert!(empty.allowed_adapter_ids.is_empty());
    }

    #[test]
    fn strict_import_rejects_corrupt_order_duplicate_resource_and_unknown_semantics() {
        let accepted = accepted_policy();
        let mut digest_bad = accepted.stored_bytes.clone();
        *digest_bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            import_policy_root(&registry(), &digest_bad)
                .unwrap_err()
                .code_str(),
            "SCB_DIGEST_MISMATCH"
        );

        let mut trailing = accepted.stored_bytes.clone();
        trailing.push(0);
        assert_eq!(
            import_policy_root(&registry(), &trailing)
                .unwrap_err()
                .code_str(),
            "SCB_TRAILING_BYTES"
        );

        let payload = manual_record(&payload_fields(&accepted.record)[..10]);
        let (stored, _) = stored_bytes(accepted.record.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_FIELD_MISSING"
        );

        let mut unordered = accepted.record.clone();
        unordered.protected_entities.swap(0, 1);
        let payload = encode_payload_manual(&unordered, ManualPayloadFault::None);
        let (stored, _) = stored_bytes(unordered.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_MAP_ORDER"
        );

        let payload =
            encode_payload_manual(&accepted.record, ManualPayloadFault::DuplicateProtected);
        let (stored, _) = stored_bytes(accepted.record.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_MAP_DUPLICATE"
        );

        let payload = encode_payload_manual(&accepted.record, ManualPayloadFault::UnknownFlag);
        let (stored, _) = stored_bytes(accepted.record.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "POLICY_ROOT_FLAG_UNKNOWN"
        );

        let payload = encode_payload_manual(&accepted.record, ManualPayloadFault::UnknownEffectTag);
        let (stored, _) = stored_bytes(accepted.record.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "POLICY_ROOT_EFFECT_KIND_UNKNOWN"
        );

        let payload =
            encode_payload_manual(&accepted.record, ManualPayloadFault::ExcessiveResource);
        let (stored, _) = stored_bytes(accepted.record.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "POLICY_ROOT_RESOURCE_LIMIT"
        );

        let oversized = vec![0_u8; MAX_STANDALONE_BYTES + 1];
        assert_eq!(
            import_policy_root(&registry(), &oversized)
                .unwrap_err()
                .code_str(),
            "SCB_RESOURCE_LIMIT"
        );
    }

    #[test]
    fn strict_import_rejects_unknown_duplicate_and_ordered_fields() {
        let accepted = accepted_policy();
        let canonical_fields = payload_fields(&accepted.record);

        let mut unknown = canonical_fields.clone();
        unknown.push((12, Vec::new()));
        let (stored, _) =
            stored_bytes(accepted.record.schema_epoch_id, &manual_record(&unknown)).unwrap();
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_FIELD_UNKNOWN"
        );

        let mut duplicate = canonical_fields.clone();
        duplicate.insert(1, duplicate[0].clone());
        let (stored, _) =
            stored_bytes(accepted.record.schema_epoch_id, &manual_record(&duplicate)).unwrap();
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_FIELD_DUPLICATE"
        );

        let mut unordered = canonical_fields;
        unordered.swap(0, 1);
        let (stored, _) =
            stored_bytes(accepted.record.schema_epoch_id, &manual_record(&unordered)).unwrap();
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_FIELD_ORDER"
        );
    }

    #[test]
    fn invalid_transition_tag_preserves_the_frozen_policy_error() {
        let accepted = accepted_policy();
        let mut fields = payload_fields(&accepted.record);
        fields[9].1 = encode_uvar(2);
        let (stored, _) =
            stored_bytes(accepted.record.schema_epoch_id, &manual_record(&fields)).unwrap();
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "POLICY_ROOT_TRANSITION_MODE_INVALID"
        );
    }

    #[test]
    fn strict_import_rejects_nonminimal_envelope_and_payload_epoch_mismatch() {
        let accepted = accepted_policy();
        let preimage = &accepted.stored_bytes[..accepted.stored_bytes.len() - ID_LEN];
        let mut nonminimal = Vec::with_capacity(preimage.len() + 1);
        nonminimal.extend_from_slice(MAGIC);
        nonminimal.extend_from_slice(&[0x81, 0x00]);
        nonminimal.extend_from_slice(&preimage[MAGIC.len() + 1..]);
        let stored = attach_root(nonminimal);
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_VARINT_NON_MINIMAL"
        );

        let mut mismatched = accepted.record.clone();
        mismatched.schema_epoch_id = SchemaEpochId::from_bytes(id(99));
        let payload = encode_payload(&mismatched).unwrap();
        let (stored, _) = stored_bytes(accepted.record.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_policy_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_EPOCH_MISMATCH"
        );
    }

    #[test]
    fn policy_self_oracle_and_protected_entity_isolation_is_pure() {
        let policy = accepted_policy();
        let base = state_with(policy.root, 0, 20, 21, 90);
        let same = state_with(policy.root, 0, 20, 21, 90);
        let report = validate_ordinary_program_isolation(&policy, &base, &same).unwrap();
        assert_eq!(report.policy_root, policy.root);
        assert_eq!(report.protected_entities_checked, 2);

        let wrong_policy = state_with(policy_root(100), 0, 20, 21, 90);
        assert_eq!(
            validate_ordinary_program_isolation(&policy, &wrong_policy, &same)
                .unwrap_err()
                .code_str(),
            "POLICY_ISOLATION_POLICY_ROOT_MISMATCH"
        );

        let changed_policy = state_with(policy_root(101), 0, 20, 21, 90);
        assert_eq!(
            validate_ordinary_program_isolation(&policy, &base, &changed_policy)
                .unwrap_err()
                .code_str(),
            "POLICY_ISOLATION_POLICY_ROOT_CHANGED"
        );

        let changed_schema = state_with(policy.root, 99, 20, 21, 90);
        assert_eq!(
            validate_ordinary_program_isolation(&policy, &base, &changed_schema)
                .unwrap_err()
                .code_str(),
            "POLICY_ISOLATION_SCHEMA_EPOCH_CHANGED"
        );

        let changed_contract = state_with(policy.root, 0, 22, 21, 90);
        assert_eq!(
            validate_ordinary_program_isolation(&policy, &base, &changed_contract)
                .unwrap_err()
                .code_str(),
            "POLICY_ISOLATION_CONTRACT_ROOT_CHANGED"
        );

        let changed_test = state_with(policy.root, 0, 20, 23, 90);
        assert_eq!(
            validate_ordinary_program_isolation(&policy, &base, &changed_test)
                .unwrap_err()
                .code_str(),
            "POLICY_ISOLATION_TEST_ROOT_CHANGED"
        );

        let changed_protected = state_with(policy.root, 0, 20, 21, 91);
        assert_eq!(
            validate_ordinary_program_isolation(&policy, &base, &changed_protected)
                .unwrap_err()
                .code_str(),
            "POLICY_ISOLATION_PROTECTED_ENTITY_CHANGED"
        );
    }

    #[test]
    fn mandatory_test_contract_finalization_requires_policy_incomplete_report() {
        let policy = accepted_policy();
        let final_plan = finalize_mandatory_contract_tests(&policy, &report()).unwrap();
        assert_eq!(final_plan.policy_root, policy.root);
        assert_eq!(final_plan.finality, PolicyPlanFinality::PolicyFinal);
        assert_eq!(final_plan.required_tests, vec![entity(50), entity(51)]);
        assert_eq!(final_plan.required_contracts, vec![entity(60), entity(61)]);
    }

    #[test]
    fn finalization_rejects_forged_or_omitted_contract_test_inputs() {
        let policy = accepted_policy();
        let mut unsorted = report();
        unsorted.tests.swap(0, 1);
        assert_eq!(
            finalize_mandatory_contract_tests(&policy, &unsorted)
                .unwrap_err()
                .code_str(),
            "POLICY_FINAL_REPORT_INVALID"
        );

        let mut omitted_contract = report();
        omitted_contract.contracts = vec![entity(60), entity(62)];
        assert_eq!(
            finalize_mandatory_contract_tests(&policy, &omitted_contract)
                .unwrap_err()
                .code_str(),
            "POLICY_FINAL_REQUIRED_CONTRACT_MISSING"
        );

        let mut omitted_test = report();
        omitted_test.tests = vec![entity(50), entity(52)];
        omitted_test.selected_tests = vec![entity(50), entity(52)];
        assert_eq!(
            finalize_mandatory_contract_tests(&policy, &omitted_test)
                .unwrap_err()
                .code_str(),
            "POLICY_FINAL_REQUIRED_TEST_MISSING"
        );

        let mut not_selected = report();
        not_selected.selected_tests = vec![entity(50), entity(52)];
        assert_eq!(
            finalize_mandatory_contract_tests(&policy, &not_selected)
                .unwrap_err()
                .code_str(),
            "POLICY_FINAL_REQUIRED_TEST_NOT_SELECTED"
        );
    }

    #[test]
    fn stable_policy_codes_are_frozen() {
        let codes = [
            PolicyRootErrorCode::DuplicateInput,
            PolicyRootErrorCode::VersionUnsupported,
            PolicyRootErrorCode::EffectKindUnknown,
            PolicyRootErrorCode::MutationClassUnknown,
            PolicyRootErrorCode::ResourceLimit,
            PolicyRootErrorCode::TransitionModeInvalid,
            PolicyRootErrorCode::FlagUnknown,
            PolicyRootErrorCode::GrantDenied,
            PolicyRootErrorCode::PolicyRootMismatch,
            PolicyRootErrorCode::WorkspaceMismatch,
            PolicyRootErrorCode::StatePolicyRootChanged,
            PolicyRootErrorCode::StateSchemaEpochChanged,
            PolicyRootErrorCode::StateContractRootChanged,
            PolicyRootErrorCode::StateTestRootChanged,
            PolicyRootErrorCode::ProtectedEntityChanged,
            PolicyRootErrorCode::FinalReportInvalid,
            PolicyRootErrorCode::RequiredTestMissing,
            PolicyRootErrorCode::RequiredContractMissing,
            PolicyRootErrorCode::RequiredTestNotSelected,
        ];
        assert_eq!(codes.len(), 19);
        for (offset, code) in codes.into_iter().enumerate() {
            assert_eq!(code.numeric(), 37_000 + u32::try_from(offset).unwrap());
            assert!(code.as_str().starts_with("POLICY_"));
        }
    }

    #[test]
    fn closed_effect_and_mutation_tag_sets_are_exact() {
        let effect_tags = [
            EffectKind::StdoutWrite,
            EffectKind::StderrWrite,
            EffectKind::FileRead,
            EffectKind::FileWrite,
            EffectKind::ClockRead,
            EffectKind::RandomRead,
            EffectKind::EnvironmentRead,
            EffectKind::AdapterCall,
        ]
        .map(EffectKind::tag);
        assert_eq!(effect_tags, [1, 2, 3, 4, 5, 6, 7, 8]);

        let mutation_tags = [
            MutationClass::CreateEntity,
            MutationClass::ReplaceEntityVersion,
            MutationClass::DeleteEntityBinding,
            MutationClass::SetScalarField,
            MutationClass::ReplaceTypedField,
            MutationClass::RetargetReference,
            MutationClass::InsertOrderedChild,
            MutationClass::RemoveOrderedChild,
            MutationClass::MoveOrderedChild,
            MutationClass::AddEntryPoint,
            MutationClass::RemoveEntryPoint,
            MutationClass::AddTest,
            MutationClass::ReplaceTest,
            MutationClass::AddContract,
            MutationClass::ReplaceContract,
            MutationClass::UpdateDependencyBinding,
        ]
        .map(MutationClass::tag);
        assert_eq!(
            mutation_tags,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn descriptor_and_decoder_mismatch_fail_closed() {
        let accepted = accepted_policy();
        let empty_registry =
            SchemaEpochRegistry::new(Vec::<RegistryEntry<PolicyRootEpoch1Decoder>>::new()).unwrap();
        assert_eq!(
            import_policy_root(&empty_registry, &accepted.stored_bytes)
                .unwrap_err()
                .code_str(),
            "SCHEMA_EPOCH_MISMATCH"
        );

        let mut record = conformance_epoch_record();
        record.contracts[0].kind_tag = 371;
        let epoch_id = record.schema_epoch_id().unwrap();
        let bad_registry = SchemaEpochRegistry::new(vec![
            RegistryEntry::new(epoch_id, record, PolicyRootEpoch1Decoder::new(epoch_id)).unwrap(),
        ])
        .unwrap();
        let mut bad_epoch_record = accepted.record.clone();
        bad_epoch_record.schema_epoch_id = epoch_id;
        let payload = encode_payload(&bad_epoch_record).unwrap();
        let (stored, _) = stored_bytes(epoch_id, &payload).unwrap();
        assert_eq!(
            import_policy_root(&bad_registry, &stored)
                .unwrap_err()
                .code_str(),
            "SCHEMA_CONTRACT_UNKNOWN"
        );
    }

    #[test]
    fn capability_issue_import_verify_and_canonical_bytes() {
        let (policy, trusted_key, token) = issued_token();
        assert_eq!(
            hex(token.digest().as_bytes()),
            "fd9248cd3f1e46ed013e97c985c8e9e45eb58277b0d8dd126f5cbfeb1698d616"
        );
        assert_eq!(
            hex(token.authenticator().as_bytes()),
            "7c4c590e61b186cd399b7cfcb3abc6481c0dc77b542fd50f6f7f3c4aebcec7ac"
        );
        assert_eq!(
            hex(blake3::hash(token.stored_bytes()).as_bytes()),
            "f7a00e1e9eb35d6b66445c47c8426d5792078b9a9de9b165d7b7c697d3c92acb"
        );
        let imported = import_capability_token(token.stored_bytes()).unwrap();
        assert_eq!(imported, token);
        assert_eq!(
            verify_capability_token(
                &policy,
                &imported,
                &trusted_key,
                &cap_verification_request()
            )
            .unwrap(),
            token.digest()
        );
        assert_eq!(
            imported.body(),
            &CapabilityTokenBody {
                version: 1,
                issuer_id: CapabilityIssuerId::from_bytes(id(10)),
                key_id: CapabilityKeyId::from_bytes(id(11)),
                principal_id: principal(3),
                workspace_id: workspace(1),
                state_root: root(7),
                effect_id: entity(80),
                effect_kind_tag: EffectKind::FileRead.tag(),
                scope_hash: ValueHash::from_bytes(id(90)),
                adapter_id: adapter(33),
                budget: cap_budget(),
                issued_unix_millis: 100,
                expiry_unix_millis: 200,
                token_nonce: CapabilityTokenNonce::from_bytes(id(13)),
                policy_root: policy.root(),
            }
        );

        let mut trailing = token.stored_bytes().to_vec();
        trailing.push(0);
        assert_eq!(
            import_capability_token(&trailing).unwrap_err().code_str(),
            "SCB_TRAILING_BYTES"
        );
    }

    #[test]
    fn t22_capability_forgery_fails_closed() {
        let (policy, trusted_key, token) = issued_token();
        let mut forged = token.clone();
        forged.authenticator = CapabilityAuthenticator::from_bytes(id(99));
        assert_eq!(
            verify_capability_token(&policy, &forged, &trusted_key, &cap_verification_request())
                .unwrap_err()
                .code_str(),
            "CAP_AUTHENTICATOR_INVALID"
        );

        let wrong_issuer = CapabilityTrustedKey::new(
            CapabilityIssuerId::from_bytes(id(20)),
            CapabilityKeyId::from_bytes(id(11)),
            CapabilitySecret::from_bytes(id(12)),
        );
        assert_eq!(
            verify_capability_token(&policy, &token, &wrong_issuer, &cap_verification_request())
                .unwrap_err()
                .code_str(),
            "CAP_ISSUER_UNTRUSTED"
        );
    }

    #[test]
    fn t23_capability_replay_expiry_and_budget_fail_closed() {
        let (policy, trusted_key, token) = issued_token();
        let mut ledger = CapabilityLedger::new();
        let request = cap_verification_request();
        let first = verify_and_charge_capability(
            &policy,
            &token,
            &trusted_key,
            &request,
            &mut ledger,
            CapabilityUseNonce::from_bytes(id(1)),
        )
        .unwrap();
        assert_eq!(
            first.spent_after,
            CapabilityResourceBudget::adapter_invocation()
        );
        let snapshot = ledger.clone();
        assert_eq!(
            verify_and_charge_capability(
                &policy,
                &token,
                &trusted_key,
                &request,
                &mut ledger,
                CapabilityUseNonce::from_bytes(id(1)),
            )
            .unwrap_err()
            .code_str(),
            "CAP_REPLAY"
        );
        assert_eq!(ledger, snapshot);

        verify_and_charge_capability(
            &policy,
            &token,
            &trusted_key,
            &request,
            &mut ledger,
            CapabilityUseNonce::from_bytes(id(2)),
        )
        .unwrap();
        let exhausted = ledger.clone();
        assert_eq!(
            verify_and_charge_capability(
                &policy,
                &token,
                &trusted_key,
                &request,
                &mut ledger,
                CapabilityUseNonce::from_bytes(id(3)),
            )
            .unwrap_err()
            .code_str(),
            "CAP_LEDGER_EXHAUSTED"
        );
        assert_eq!(ledger, exhausted);

        let mut expired = request.clone();
        expired.now_unix_millis = 200;
        assert_eq!(
            verify_capability_token(&policy, &token, &trusted_key, &expired)
                .unwrap_err()
                .code_str(),
            "CAP_EXPIRED"
        );

        let mut stale_root = request;
        stale_root.state_root = root(8);
        assert_eq!(
            verify_capability_token(&policy, &token, &trusted_key, &stale_root)
                .unwrap_err()
                .code_str(),
            "CAP_STATE_ROOT_MISMATCH"
        );
    }

    #[test]
    fn t24_capability_scope_workspace_effect_and_adapter_confusion_fail_closed() {
        let (policy, trusted_key, token) = issued_token();
        let mut request = cap_verification_request();
        request.scope_hash = ValueHash::from_bytes(id(91));
        assert_eq!(
            verify_capability_token(&policy, &token, &trusted_key, &request)
                .unwrap_err()
                .code_str(),
            "CAP_SCOPE_MISMATCH"
        );

        let mut request = cap_verification_request();
        request.workspace_id = workspace(2);
        assert_eq!(
            verify_capability_token(&policy, &token, &trusted_key, &request)
                .unwrap_err()
                .code_str(),
            "CAP_WORKSPACE_MISMATCH"
        );

        let mut request = cap_verification_request();
        request.effect_id = entity(81);
        assert_eq!(
            verify_capability_token(&policy, &token, &trusted_key, &request)
                .unwrap_err()
                .code_str(),
            "CAP_EFFECT_MISMATCH"
        );

        let mut request = cap_verification_request();
        request.adapter_id = adapter(34);
        assert_eq!(
            verify_capability_token(&policy, &token, &trusted_key, &request)
                .unwrap_err()
                .code_str(),
            "CAP_ADAPTER_MISMATCH"
        );
    }

    #[test]
    fn capability_issuance_requires_policy_grant_and_bounded_budget() {
        let policy = accepted_policy();
        let trusted_key = cap_trusted_key();
        let mut no_principal = cap_request();
        no_principal.principal_id = principal(4);
        assert_eq!(
            issue_capability_token(&policy, &trusted_key, &no_principal)
                .unwrap_err()
                .code_str(),
            "CAP_GRANT_DENIED"
        );

        let mut zero_budget = cap_request();
        zero_budget.budget = CapabilityResourceBudget::zero();
        assert_eq!(
            issue_capability_token(&policy, &trusted_key, &zero_budget)
                .unwrap_err()
                .code_str(),
            "CAP_BUDGET_ZERO"
        );

        let mut excessive_budget = cap_request();
        excessive_budget.budget = CapabilityResourceBudget::new(101, 2, 3, 1, 0, 1);
        assert_eq!(
            issue_capability_token(&policy, &trusted_key, &excessive_budget)
                .unwrap_err()
                .code_str(),
            "CAP_BUDGET_EXCEEDED"
        );
    }

    #[test]
    fn stable_capability_error_codes_are_exact() {
        assert_eq!(CapabilityErrorCode::VersionUnsupported.numeric(), 38_000);
        assert_eq!(CapabilityErrorCode::IssuerUntrusted.numeric(), 38_001);
        assert_eq!(CapabilityErrorCode::KeyUntrusted.numeric(), 38_002);
        assert_eq!(CapabilityErrorCode::AuthenticatorInvalid.numeric(), 38_003);
        assert_eq!(CapabilityErrorCode::PolicyRootMismatch.numeric(), 38_004);
        assert_eq!(CapabilityErrorCode::WorkspaceMismatch.numeric(), 38_005);
        assert_eq!(CapabilityErrorCode::PrincipalMismatch.numeric(), 38_006);
        assert_eq!(CapabilityErrorCode::StateRootMismatch.numeric(), 38_007);
        assert_eq!(CapabilityErrorCode::EffectMismatch.numeric(), 38_008);
        assert_eq!(CapabilityErrorCode::ScopeMismatch.numeric(), 38_009);
        assert_eq!(CapabilityErrorCode::AdapterMismatch.numeric(), 38_010);
        assert_eq!(CapabilityErrorCode::Expired.numeric(), 38_011);
        assert_eq!(CapabilityErrorCode::TimeInvalid.numeric(), 38_012);
        assert_eq!(CapabilityErrorCode::BudgetZero.numeric(), 38_013);
        assert_eq!(CapabilityErrorCode::BudgetExceeded.numeric(), 38_014);
        assert_eq!(CapabilityErrorCode::GrantDenied.numeric(), 38_015);
        assert_eq!(CapabilityErrorCode::Replay.numeric(), 38_016);
        assert_eq!(CapabilityErrorCode::LedgerExhausted.numeric(), 38_017);
        assert_eq!(CapabilityErrorCode::CanonicalInvalid.numeric(), 38_018);
        assert_eq!(CapabilityErrorCode::InternalInvariant.numeric(), 38_019);
    }

    #[derive(Clone, Copy)]
    enum ManualPayloadFault {
        None,
        DuplicateProtected,
        UnknownFlag,
        UnknownEffectTag,
        ExcessiveResource,
    }

    fn encode_payload_manual(record: &PolicyRootRecord, fault: ManualPayloadFault) -> Vec<u8> {
        let mut manual = record.clone();
        if matches!(fault, ManualPayloadFault::DuplicateProtected) {
            manual
                .protected_entities
                .insert(1, manual.protected_entities[0]);
        }
        if matches!(fault, ManualPayloadFault::UnknownFlag) {
            manual.interpretation_flags.push(1);
        }
        if matches!(fault, ManualPayloadFault::UnknownEffectTag) {
            manual.principal_grants[0]
                .1
                .allowed_effect_kind_tags
                .push(99);
            manual.principal_grants[0]
                .1
                .allowed_effect_kind_tags
                .sort_unstable();
        }
        if matches!(fault, ManualPayloadFault::ExcessiveResource) {
            manual.principal_grants[0].1.resource_ceilings.max_fuel =
                MAX_POLICY_RESOURCE_CEILING + 1;
        }
        let mut fields = payload_fields(&manual);
        if matches!(fault, ManualPayloadFault::DuplicateProtected) {
            fields[5].1 = encode_id_set(&manual.protected_entities).unwrap();
        }
        manual_record(&fields)
    }

    fn payload_fields(record: &PolicyRootRecord) -> Vec<(u32, Vec<u8>)> {
        vec![
            (1, record.workspace_id.as_bytes().to_vec()),
            (2, record.schema_epoch_id.as_bytes().to_vec()),
            (3, encode_uvar(u64::from(record.policy_schema_version))),
            (4, encode_option_policy_root(record.parent_policy).unwrap()),
            (5, encode_grants_manual(record)),
            (6, encode_id_set(&record.protected_entities).unwrap()),
            (7, encode_id_set(&record.required_tests).unwrap()),
            (8, encode_id_set(&record.required_contracts).unwrap()),
            (9, encode_option_uvar(record.expiry_unix_millis).unwrap()),
            (10, encode_uvar(u64::from(record.transition_mode.tag()))),
            (11, encode_u32_set(&record.interpretation_flags).unwrap()),
        ]
    }

    fn encode_grants_manual(record: &PolicyRootRecord) -> Vec<u8> {
        encode_map(
            &record
                .principal_grants
                .iter()
                .map(|(principal_id, grant)| {
                    (
                        principal_id.as_bytes().to_vec(),
                        encode_principal_grant(grant).unwrap(),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn manual_record(fields: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = encode_uvar(fields.len() as u64);
        for (tag, value) in fields {
            out.extend_from_slice(&encode_uvar(u64::from(*tag)));
            out.extend_from_slice(&encode_uvar(value.len() as u64));
            out.extend_from_slice(value);
        }
        out
    }

    fn attach_root(mut preimage: Vec<u8>) -> Vec<u8> {
        let root = PolicyRootId::derive(&preimage);
        preimage.extend_from_slice(root.as_bytes());
        preimage
    }

    trait Single<T> {
        fn single(&self) -> Option<&T>;
    }

    impl<T> Single<T> for [T] {
        fn single(&self) -> Option<&T> {
            if self.len() == 1 { self.first() } else { None }
        }
    }

    #[test]
    fn manual_hex_decode_helper_round_trips() {
        let bytes = from_hex("00ff10");
        assert_eq!(hex(bytes), "00ff10");
    }
}
