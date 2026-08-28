#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use core::fmt;

use sley_id::{BytecodeCacheKey, EntityId, SchemaEpochId, StateRoot};

mod execute;
mod lower;

pub use execute::{
    ExecutionError, ExecutionErrorCode, ExecutionLimits, ExecutionOutcome, ExecutionRequest,
    ExecutionStatusCode, ExecutionTermination, MAX_EXECUTION_INPUT_VALUE_UNITS,
    MAX_EXECUTION_INPUTS, MAX_OBSERVATION_PREIMAGE_BYTES, ResourceKind, derive_observation_id,
    execute_function, execution_value_units, validated_execution_input_hashes,
};
pub use lower::{
    BlockSlot, BytecodeBlock, BytecodeFunction, BytecodeSwitchArgument, BytecodeSwitchCase,
    BytecodeSwitchEdge, BytecodeTargetEdge, BytecodeTerminator, Instruction, LoweredFunction,
    LoweringError, LoweringInput, Register, lower_function,
};

/// Frozen S20-260 SSMC1 field-schema hash.
pub const SSMC1_FIELD_SCHEMA_HASH: [u8; 32] = [
    0x19, 0x83, 0xbc, 0x8d, 0x6a, 0xd9, 0xac, 0x3c, 0xb5, 0x39, 0x08, 0x53, 0xf4, 0x39, 0x59, 0xcf,
    0x2c, 0x3d, 0xc0, 0xae, 0x8e, 0x0c, 0xa1, 0x8c, 0xa8, 0x26, 0x4c, 0xa4, 0x96, 0x01, 0x33, 0xae,
];
/// Frozen SSMC1 decoder-limits hash.
pub const SSMC1_DECODER_LIMITS_HASH: [u8; 32] = [
    0x38, 0x97, 0x91, 0xb1, 0x70, 0xbc, 0x9d, 0x85, 0x75, 0xf7, 0xe6, 0xf3, 0x38, 0xe4, 0xf9, 0xe9,
    0xf2, 0xb7, 0x5f, 0x35, 0xd7, 0xa2, 0xe5, 0x2c, 0x7c, 0xb1, 0x06, 0xcb, 0x2c, 0xd6, 0x13, 0x6a,
];

/// Stable restricted lowering failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LowerErrorCode {
    /// `VM_LOWER_PROFILE_UNSUPPORTED`.
    ProfileUnsupported,
    /// `VM_LOWER_OPCODE_UNSUPPORTED`.
    OpcodeUnsupported,
    /// `VM_LOWER_SIGNATURE_MISMATCH`.
    SignatureMismatch,
    /// `VM_LOWER_IMMEDIATE_MISMATCH`.
    ImmediateMismatch,
    /// `VM_LOWER_LOCAL_REFERENCE_INVALID`.
    LocalReferenceInvalid,
    /// `VM_LOWER_CACHE_KEY_UNSUPPORTED`.
    CacheKeyUnsupported,
    /// `VM_LOWER_RESOURCE_LIMIT`.
    ResourceLimit,
}

impl LowerErrorCode {
    /// Returns the stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfileUnsupported => "VM_LOWER_PROFILE_UNSUPPORTED",
            Self::OpcodeUnsupported => "VM_LOWER_OPCODE_UNSUPPORTED",
            Self::SignatureMismatch => "VM_LOWER_SIGNATURE_MISMATCH",
            Self::ImmediateMismatch => "VM_LOWER_IMMEDIATE_MISMATCH",
            Self::LocalReferenceInvalid => "VM_LOWER_LOCAL_REFERENCE_INVALID",
            Self::CacheKeyUnsupported => "VM_LOWER_CACHE_KEY_UNSUPPORTED",
            Self::ResourceLimit => "VM_LOWER_RESOURCE_LIMIT",
        }
    }

    /// Returns the stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::ProfileUnsupported => 26_000,
            Self::OpcodeUnsupported => 26_001,
            Self::SignatureMismatch => 26_002,
            Self::ImmediateMismatch => 26_003,
            Self::LocalReferenceInvalid => 26_004,
            Self::CacheKeyUnsupported => 26_005,
            Self::ResourceLimit => 26_006,
        }
    }
}

impl fmt::Display for LowerErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One stable lowering failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LowerError(LowerErrorCode);

impl LowerError {
    /// Constructs a failure.
    #[must_use]
    pub const fn new(code: LowerErrorCode) -> Self {
        Self(code)
    }

    /// Returns the stable code.
    #[must_use]
    pub const fn code(&self) -> LowerErrorCode {
        self.0
    }
}

impl fmt::Display for LowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for LowerError {}

/// Caller-selected cache/lowering profile fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheProfile {
    /// Requested VM semantic version.
    pub vm_version: [u32; 3],
    /// Requested lowering profile tag.
    pub lowering_profile: u32,
    /// Requested lowerer semantic version.
    pub lowerer_version: [u32; 3],
    /// Entry generic argument count.
    pub entry_type_arguments: u64,
    /// Adapter ABI entry count.
    pub adapter_abi_entries: u64,
    /// Canonical execution ABI flags.
    pub execution_abi_flags: u64,
}

impl CacheProfile {
    /// Exact restricted epoch-1 profile.
    pub const RESTRICTED_V1: Self = Self {
        vm_version: [1, 0, 0],
        lowering_profile: 1,
        lowerer_version: [1, 0, 0],
        entry_type_arguments: 0,
        adapter_abi_entries: 0,
        execution_abi_flags: 0,
    };
}

/// Builds the exact restricted bytecode cache-key preimage.
///
/// # Errors
///
/// Returns `VM_LOWER_CACHE_KEY_UNSUPPORTED` unless every requested profile
/// field exactly matches the restricted profile.
pub fn cache_key_preimage(
    schema_epoch: SchemaEpochId,
    state_root: StateRoot,
    entry_function: EntityId,
    profile: CacheProfile,
) -> Result<Vec<u8>, LowerError> {
    if profile != CacheProfile::RESTRICTED_V1 {
        return Err(LowerError::new(LowerErrorCode::CacheKeyUnsupported));
    }
    let mut preimage = Vec::with_capacity(224);
    preimage.extend_from_slice(b"SLEYBCK1");
    push_u32(&mut preimage, 1);
    preimage.extend_from_slice(schema_epoch.as_bytes());
    preimage.extend_from_slice(&SSMC1_FIELD_SCHEMA_HASH);
    preimage.extend_from_slice(&SSMC1_DECODER_LIMITS_HASH);
    preimage.extend_from_slice(state_root.as_bytes());
    preimage.extend_from_slice(entry_function.as_bytes());
    for part in profile.vm_version {
        push_u32(&mut preimage, part);
    }
    push_u32(&mut preimage, profile.lowering_profile);
    for part in profile.lowerer_version {
        push_u32(&mut preimage, part);
    }
    preimage.extend_from_slice(&profile.entry_type_arguments.to_be_bytes());
    preimage.extend_from_slice(&profile.adapter_abi_entries.to_be_bytes());
    preimage.extend_from_slice(&profile.execution_abi_flags.to_be_bytes());
    debug_assert_eq!(preimage.len(), 224);
    Ok(preimage)
}

/// Derives the exact restricted bytecode cache key.
///
/// # Errors
///
/// Returns `VM_LOWER_CACHE_KEY_UNSUPPORTED` unless every requested profile
/// field exactly matches the restricted profile.
pub fn derive_cache_key(
    schema_epoch: SchemaEpochId,
    state_root: StateRoot,
    entry_function: EntityId,
    profile: CacheProfile,
) -> Result<BytecodeCacheKey, LowerError> {
    Ok(BytecodeCacheKey::derive(cache_key_preimage(
        schema_epoch,
        state_root,
        entry_function,
        profile,
    )?))
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::*;

    #[test]
    fn cache_key_is_exact_and_profile_bound() {
        let preimage = cache_key_preimage(
            SchemaEpochId::from_bytes([1; 32]),
            StateRoot::from_bytes([2; 32]),
            EntityId::from_bytes([3; 32]),
            CacheProfile::RESTRICTED_V1,
        )
        .unwrap();
        let mut preimage_hex = String::with_capacity(preimage.len() * 2);
        for byte in preimage {
            write!(&mut preimage_hex, "{byte:02x}").unwrap();
        }
        assert_eq!(
            preimage_hex,
            concat!(
                "534c455942434b3100000001",
                "0101010101010101010101010101010101010101010101010101010101010101",
                "1983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae",
                "389791b170bc9d8575f7e6f338e4f9e9f2b75f35d7a2e52c7cb106cb2cd6136a",
                "0202020202020202020202020202020202020202020202020202020202020202",
                "0303030303030303030303030303030303030303030303030303030303030303",
                "00000001000000000000000000000001",
                "000000010000000000000000",
                "000000000000000000000000000000000000000000000000"
            )
        );
        let key = derive_cache_key(
            SchemaEpochId::from_bytes([1; 32]),
            StateRoot::from_bytes([2; 32]),
            EntityId::from_bytes([3; 32]),
            CacheProfile::RESTRICTED_V1,
        )
        .unwrap();
        assert_eq!(
            key.as_bytes(),
            &[
                35, 174, 239, 189, 35, 216, 56, 166, 169, 47, 240, 86, 71, 136, 67, 197, 132, 39,
                135, 186, 194, 214, 52, 156, 238, 134, 138, 141, 84, 176, 140, 180,
            ]
        );
        assert_eq!(
            key,
            derive_cache_key(
                SchemaEpochId::from_bytes([1; 32]),
                StateRoot::from_bytes([2; 32]),
                EntityId::from_bytes([3; 32]),
                CacheProfile::RESTRICTED_V1,
            )
            .unwrap()
        );
        let mut unsupported = CacheProfile::RESTRICTED_V1;
        unsupported.execution_abi_flags = 1;
        assert_eq!(
            derive_cache_key(
                SchemaEpochId::from_bytes([1; 32]),
                StateRoot::from_bytes([2; 32]),
                EntityId::from_bytes([3; 32]),
                unsupported,
            )
            .unwrap_err()
            .code(),
            LowerErrorCode::CacheKeyUnsupported
        );
        assert_ne!(key.as_bytes(), &[0; 32]);
    }
}
