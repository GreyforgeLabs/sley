#![forbid(unsafe_code)]
#![doc = "Restricted deterministic reference adapter fixtures for S20-280."]

use std::collections::BTreeMap;

use sley_check::{TypeEnvironment, TypeError};
use sley_id::{
    AdapterStateId, AdapterTranscriptId, EntityId, PrincipalId, ReferenceAdapterId, SchemaEpochId,
    StateRoot, ValueHash,
};
use sley_policy::{
    AcceptedPolicyRoot, CapabilityChargeReceipt, CapabilityError, CapabilityErrorCode,
    CapabilityLedger, CapabilityResourceBudget, CapabilityToken, CapabilityTrustedKey,
    CapabilityUseNonce, CapabilityVerificationRequest, verify_and_charge_capability,
};
use sley_ssmc::fingerprint::{FingerprintError, hash_validated_value};
use sley_ssmc::{
    AdapterImport, ConstData, ConstValue, EffectDefinition, EffectKind, IntegerWidth, TypeExpr,
};

const PROFILE_VERSION: u32 = 1;
const MAX_FILES: u64 = 4_096;
const MAX_ENV: u64 = 4_096;
const MAX_REPLAY: u64 = 65_535;
const MAX_TICKS: u64 = 1_000_000;
const MAX_BLOB: u64 = 16_777_216;
const MAX_PREIMAGE: u64 = 67_108_864;
const MAX_PATH_COMPONENT_BYTES: usize = 255;
const MAX_REQUEST_PATH_BYTES: usize = 4_096;
const MAX_CANONICAL_PATH_BYTES: u64 = 4_352;
const ENCODED_FILE_ENTRY_OVERHEAD: u64 = 16;

/// Stable S20-280 reference adapter failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AdapterErrorCode {
    /// Unsupported reference profile or kind.
    ProfileUnsupported = 28_000,
    /// Import adapter identity does not match the selected reference kind.
    IdentityMismatch = 28_001,
    /// Import ABI version is not exactly 1.
    AbiMismatch = 28_002,
    /// Import/effect binding is not exactly one adapter-call effect.
    EffectMismatch = 28_003,
    /// Constant, hashability, or exact type check failed.
    TypeMismatch = 28_004,
    /// Fixture state is not canonical.
    StateInvalid = 28_005,
    /// Virtual path input is not canonical.
    PathInvalid = 28_006,
    /// Generic replay entry does not match this invocation.
    ReplayMismatch = 28_007,
    /// Generic replay has no next entry.
    ReplayExhausted = 28_008,
    /// A resource limit would be exceeded.
    ResourceLimit = 28_009,
    /// Cancellation point was reached before mutation.
    Cancelled = 28_010,
    /// Internal invariant failed.
    InternalInvariant = 28_011,
}

impl AdapterErrorCode {
    /// Returns the frozen numeric error code.
    #[must_use]
    pub const fn code(self) -> u32 {
        self as u32
    }
}

/// One deterministic reference adapter kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ReferenceAdapterKind {
    /// Append bytes to captured stdout.
    Stdout = 1,
    /// Append bytes to captured stderr.
    Stderr = 2,
    /// Read a request-owned virtual file.
    VirtualFileRead = 3,
    /// Replace a request-owned virtual file.
    VirtualFileWrite = 4,
    /// Consume a configured deterministic tick.
    Clock = 5,
    /// Emit deterministic random bytes.
    Random = 6,
    /// Look up a request-owned environment entry.
    Environment = 7,
    /// Consume a typed replay fixture entry.
    GenericReplay = 8,
}

impl ReferenceAdapterKind {
    /// Returns this kind's frozen tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        self as u32
    }

    /// Returns the exact derived reference adapter identity.
    #[must_use]
    pub fn reference_id(self) -> ReferenceAdapterId {
        ReferenceAdapterId::derive_kind(self.tag())
    }
}

/// Request-supplied hard adapter limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterLimits {
    /// Maximum committed adapter calls.
    pub max_calls: u64,
    /// Maximum committed action count.
    pub max_actions: u64,
    /// Maximum combined stdout/stderr bytes.
    pub max_output_bytes: u64,
    /// Maximum virtual file entries.
    pub max_virtual_files: u64,
    /// Maximum bytes in one virtual file.
    pub max_virtual_file_bytes: u64,
    /// Maximum total virtual file bytes.
    pub max_total_virtual_file_bytes: u64,
    /// Maximum random bytes in one request.
    pub max_random_bytes: u64,
    /// Maximum state preimage bytes.
    pub max_state_preimage_bytes: u64,
    /// Maximum transcript preimage bytes.
    pub max_transcript_preimage_bytes: u64,
}

impl AdapterLimits {
    /// Returns profile-maximum limits.
    #[must_use]
    pub const fn profile_max() -> Self {
        Self {
            max_calls: u64::MAX,
            max_actions: u64::MAX,
            max_output_bytes: MAX_PREIMAGE,
            max_virtual_files: MAX_FILES,
            max_virtual_file_bytes: MAX_BLOB,
            max_total_virtual_file_bytes: MAX_PREIMAGE,
            max_random_bytes: MAX_BLOB,
            max_state_preimage_bytes: MAX_PREIMAGE,
            max_transcript_preimage_bytes: MAX_PREIMAGE,
        }
    }
}

/// One adapter invocation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterInvocation {
    /// Selected reference kind.
    pub kind: ReferenceAdapterKind,
    /// Exact resource scope constant.
    pub scope: ConstValue,
    /// Exact request constant.
    pub request: ConstValue,
    /// Request limits.
    pub limits: AdapterLimits,
    /// Optional cancellation action threshold.
    pub cancel_at_action: Option<u64>,
}

/// Stored generic replay outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterOutcome {
    /// Successful adapter response.
    Success(ConstValue),
    /// Declared failure response.
    DeclaredFailure(ConstValue),
}

/// One request-owned generic replay fixture entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayEntry {
    /// Expected import identity.
    pub import_id: EntityId,
    /// Expected raw adapter identity.
    pub adapter_id: [u8; 32],
    /// Expected ABI version.
    pub abi_version: u32,
    /// Expected call index.
    pub call_index: u64,
    /// Expected scope value hash.
    pub scope_hash: ValueHash,
    /// Expected request value hash.
    pub request_hash: ValueHash,
    /// Stored typed outcome.
    pub outcome: AdapterOutcome,
}

/// Complete request-owned fixture state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdapterFixtureState {
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes.
    pub stderr: Vec<u8>,
    /// Canonical virtual file map.
    pub virtual_files: BTreeMap<String, Vec<u8>>,
    /// Deterministic clock ticks.
    pub clock_ticks: Vec<u64>,
    /// Next clock tick index.
    pub clock_cursor: u64,
    /// Random seed.
    pub random_seed: [u8; 32],
    /// Next random block counter.
    pub random_counter: u64,
    /// Canonical request-owned environment.
    pub environment: BTreeMap<String, String>,
    /// Ordered generic replay entries.
    pub replay_entries: Vec<ReplayEntry>,
    /// Next replay entry index.
    pub replay_cursor: u64,
    /// Committed adapter call count.
    pub call_count: u64,
    /// Committed adapter action count.
    pub action_count: u64,
}

/// Successful invocation receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterReceipt {
    /// Typed adapter outcome.
    pub outcome: AdapterOutcome,
    /// Pre-invocation state ID.
    pub pre_state: AdapterStateId,
    /// Post-invocation state ID.
    pub post_state: AdapterStateId,
    /// Pre-invocation call index.
    pub call_index: u64,
    /// Actions used by this invocation.
    pub actions_used: u64,
    /// Combined captured output bytes after invocation.
    pub output_bytes: u64,
    /// Complete transcript ID.
    pub transcript: AdapterTranscriptId,
}

/// Adapter invocation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterError {
    code: AdapterErrorCode,
}

impl AdapterError {
    /// Constructs an adapter failure from a stable code.
    #[must_use]
    pub const fn new(code: AdapterErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable code.
    #[must_use]
    pub const fn code(&self) -> AdapterErrorCode {
        self.code
    }
}

/// A failure from the preserved type/fingerprint boundary or this adapter profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterInvocationError {
    /// Exact S20-210 type-system failure.
    Type(TypeError),
    /// Exact S20-250 value-hash failure.
    Fingerprint(FingerprintError),
    /// Stable S20-280 adapter-profile failure.
    Adapter(AdapterError),
}

impl AdapterInvocationError {
    /// Returns the adapter code when this is an S20-280-owned failure.
    #[must_use]
    pub const fn adapter_code(&self) -> Option<AdapterErrorCode> {
        match self {
            Self::Adapter(error) => Some(error.code()),
            Self::Type(_) | Self::Fingerprint(_) => None,
        }
    }
}

impl From<TypeError> for AdapterInvocationError {
    fn from(error: TypeError) -> Self {
        Self::Type(error)
    }
}

impl From<FingerprintError> for AdapterInvocationError {
    fn from(error: FingerprintError) -> Self {
        Self::Fingerprint(error)
    }
}

impl From<AdapterError> for AdapterInvocationError {
    fn from(error: AdapterError) -> Self {
        Self::Adapter(error)
    }
}

/// Result preserving prior-phase failures at the adapter boundary.
pub type Result<T> = std::result::Result<T, AdapterInvocationError>;

/// Authorized S20-380 adapter invocation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedAdapterInvocationError {
    /// Local type/hash preauthorization failed before ledger charge.
    PreAuthorization(AdapterInvocationError),
    /// Capability verification or ledger charge failed before fixture execution.
    Capability(CapabilityError),
    /// The capability was verified and charged, then S20-280 fixture execution failed.
    AdapterAfterAuthorization {
        /// Receipt proving the charge was consumed before fixture execution.
        charge_receipt: Box<CapabilityChargeReceipt>,
        /// Exact S20-280 adapter failure.
        error: AdapterInvocationError,
    },
}

impl AuthorizedAdapterInvocationError {
    /// Returns the S20-280 adapter code when this error carries one.
    #[must_use]
    pub const fn adapter_code(&self) -> Option<AdapterErrorCode> {
        match self {
            Self::PreAuthorization(error) | Self::AdapterAfterAuthorization { error, .. } => {
                error.adapter_code()
            }
            Self::Capability(_) => None,
        }
    }

    /// Returns the S20-380 capability error when this is a capability failure.
    #[must_use]
    pub const fn capability_error(&self) -> Option<&CapabilityError> {
        match self {
            Self::Capability(error) => Some(error),
            Self::PreAuthorization(_) | Self::AdapterAfterAuthorization { .. } => None,
        }
    }
}

/// Successful authorized adapter invocation receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedAdapterReceipt {
    /// Capability-ledger charge consumed before fixture execution.
    pub capability_receipt: CapabilityChargeReceipt,
    /// Deterministic S20-280 adapter receipt.
    pub adapter_receipt: AdapterReceipt,
}

/// Explicit host-owned authorization inputs for one adapter invocation.
pub struct AdapterAuthorization<'a> {
    /// Accepted policy root used for runtime judgment.
    pub policy: &'a AcceptedPolicyRoot,
    /// Authenticated capability token.
    pub token: &'a CapabilityToken,
    /// Trusted issuer/key/secret tuple.
    pub trusted_key: &'a CapabilityTrustedKey,
    /// Caller-owned replay/budget ledger.
    pub ledger: &'a mut CapabilityLedger,
    /// Principal attempting the invocation.
    pub principal_id: PrincipalId,
    /// Explicit host-supplied verification time.
    pub now_unix_millis: u64,
    /// Exact per-use nonce to consume if authorization succeeds.
    pub use_nonce: CapabilityUseNonce,
}

/// Result preserving authorization and adapter failures.
pub type AuthorizedResult<T> = std::result::Result<T, AuthorizedAdapterInvocationError>;

/// Derives the conservative capability charge for one adapter-limit envelope.
///
/// Fuel binds the requested action ceiling. Output binds the captured-output
/// ceiling. Memory conservatively reserves two fixture-state preimages, one
/// transcript preimage, the random-response ceiling, the captured-output
/// ceiling, virtual-file contents, and worst-case encoded path/length overhead
/// for every allowed virtual file. Effect and adapter-call counts are one;
/// mutation count is zero because S20-280 fixture writes are effects, not
/// S20-340 repository mutations.
///
/// # Errors
///
/// Returns `CAP_BUDGET_EXCEEDED` if the exact conservative memory sum cannot be
/// represented as `u64`. Policy/token ceilings are checked by S20-380
/// verification before the ledger or fixture can mutate.
pub fn capability_budget_for_adapter_limits(
    limits: AdapterLimits,
) -> std::result::Result<CapabilityResourceBudget, CapabilityError> {
    let per_file_overhead = MAX_CANONICAL_PATH_BYTES
        .checked_add(ENCODED_FILE_ENTRY_OVERHEAD)
        .ok_or(CapabilityError::Capability(
            CapabilityErrorCode::BudgetExceeded,
        ))?;
    let file_overhead = limits
        .max_virtual_files
        .checked_mul(per_file_overhead)
        .ok_or(CapabilityError::Capability(
            CapabilityErrorCode::BudgetExceeded,
        ))?;
    let memory_bytes = limits
        .max_state_preimage_bytes
        .checked_mul(2)
        .and_then(|value| value.checked_add(limits.max_transcript_preimage_bytes))
        .and_then(|value| value.checked_add(limits.max_random_bytes))
        .and_then(|value| value.checked_add(limits.max_output_bytes))
        .and_then(|value| value.checked_add(limits.max_total_virtual_file_bytes))
        .and_then(|value| value.checked_add(file_overhead))
        .ok_or(CapabilityError::Capability(
            CapabilityErrorCode::BudgetExceeded,
        ))?;
    Ok(CapabilityResourceBudget::new(
        limits.max_actions,
        memory_bytes,
        limits.max_output_bytes,
        1,
        0,
        1,
    ))
}

/// Verifies and charges S20-380 capability before invoking a reference fixture.
///
/// The existing fixture call is still clone-before-commit and remains
/// conformance-only. This wrapper is the authority boundary for S20-380's
/// narrow local profile.
///
/// # Errors
///
/// Failures before successful authorization do not mutate the ledger or
/// fixture. After successful authorization the ledger charge is consumed even
/// when fixture execution fails; fixture state remains protected by the
/// underlying S20-280 atomic clone-before-commit semantics.
#[allow(clippy::too_many_arguments)]
pub fn invoke_authorized_reference_adapter(
    state: &mut AdapterFixtureState,
    import: &AdapterImport,
    effect: &EffectDefinition,
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    state_root: StateRoot,
    invocation: &AdapterInvocation,
    authorization: AdapterAuthorization<'_>,
) -> AuthorizedResult<AuthorizedAdapterReceipt> {
    let AdapterAuthorization {
        policy,
        token,
        trusted_key,
        ledger,
        principal_id,
        now_unix_millis,
        use_nonce,
    } = authorization;
    let scope_hash = hash_const(types, schema_epoch, &invocation.scope)
        .map_err(AuthorizedAdapterInvocationError::PreAuthorization)?;
    let required_budget = capability_budget_for_adapter_limits(invocation.limits)
        .map_err(AuthorizedAdapterInvocationError::Capability)?;
    let request = CapabilityVerificationRequest {
        principal_id,
        workspace_id: policy.record().workspace_id,
        state_root,
        effect_id: effect.entity_id,
        effect_kind: effect.effect_kind,
        scope_hash,
        adapter_id: ReferenceAdapterId::from_bytes(import.adapter_id),
        now_unix_millis,
        required_budget,
    };
    let capability_receipt =
        verify_and_charge_capability(policy, token, trusted_key, &request, ledger, use_nonce)
            .map_err(AuthorizedAdapterInvocationError::Capability)?;
    match invoke_reference_adapter(
        state,
        import,
        effect,
        types,
        schema_epoch,
        state_root,
        invocation,
    ) {
        Ok(adapter_receipt) => Ok(AuthorizedAdapterReceipt {
            capability_receipt,
            adapter_receipt,
        }),
        Err(error) => Err(
            AuthorizedAdapterInvocationError::AdapterAfterAuthorization {
                charge_receipt: Box::new(capability_receipt),
                error,
            },
        ),
    }
}

/// Invokes one restricted reference adapter against caller-owned fixture state.
///
/// This is a conformance-only fixture API. It performs no protected policy,
/// capability, issuer, replay-ledger, or live-host authorization.
///
/// # Errors
///
/// Returns the first deterministic S20-280 failure. The fixture is unchanged on
/// any error.
pub fn invoke_reference_adapter(
    state: &mut AdapterFixtureState,
    import: &AdapterImport,
    effect: &EffectDefinition,
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    state_root: StateRoot,
    invocation: &AdapterInvocation,
) -> Result<AdapterReceipt> {
    validate_upstream_types(import, effect, types, invocation)?;
    preflight_state(state, invocation.limits)?;
    validate_boundary(import, effect, invocation)?;
    validate_state(state)?;

    let pre_state = state_id(
        state,
        types,
        schema_epoch,
        invocation.limits.max_state_preimage_bytes,
    )?;
    charge_cancel(state, invocation.cancel_at_action, 0)?;
    if state.call_count >= invocation.limits.max_calls {
        return fail(AdapterErrorCode::ResourceLimit);
    }

    let call_index = state.call_count;
    let start_actions = state.action_count;
    let mut next = state.clone();
    charge(&mut next, invocation.cancel_at_action, invocation.limits, 1)?;
    let outcome = plan_handler(
        &mut next,
        import,
        types,
        schema_epoch,
        invocation,
        call_index,
    )?;
    validate_outcome(types, effect, &outcome)?;
    next.call_count = next
        .call_count
        .checked_add(1)
        .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
    let post_state = state_id(
        &next,
        types,
        schema_epoch,
        invocation.limits.max_state_preimage_bytes,
    )?;
    let actions_used = next
        .action_count
        .checked_sub(start_actions)
        .ok_or_else(|| AdapterError::new(AdapterErrorCode::InternalInvariant))?;
    let output_bytes = captured_output_bytes(&next)?;
    let transcript = transcript_id(&TranscriptInput {
        types,
        schema_epoch,
        root: state_root,
        import,
        effect,
        invocation,
        call_index,
        pre_state,
        post_state,
        outcome: &outcome,
        actions_used,
        output_bytes,
        max_preimage_bytes: invocation.limits.max_transcript_preimage_bytes,
    })?;
    *state = next;
    Ok(AdapterReceipt {
        outcome,
        pre_state,
        post_state,
        call_index,
        actions_used,
        output_bytes,
        transcript,
    })
}

/// Computes a deterministic fixture state ID.
///
/// # Errors
///
/// Returns a resource or canonical state failure.
pub fn state_id(
    state: &AdapterFixtureState,
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    max_preimage_bytes: u64,
) -> Result<AdapterStateId> {
    Ok(AdapterStateId::derive(state_preimage(
        state,
        types,
        schema_epoch,
        max_preimage_bytes,
    )?))
}

fn state_preimage(
    state: &AdapterFixtureState,
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    max_preimage_bytes: u64,
) -> Result<Vec<u8>> {
    validate_state(state)?;
    let mut enc = Encoder::new(max_preimage_bytes);
    enc.fixed(b"SLEYADS1")?;
    enc.u32(PROFILE_VERSION)?;
    enc.bytes(&state.stdout)?;
    enc.bytes(&state.stderr)?;
    enc.map_bytes(&state.virtual_files)?;
    enc.u64_list(&state.clock_ticks)?;
    enc.u64(state.clock_cursor)?;
    enc.fixed(&state.random_seed)?;
    enc.u64(state.random_counter)?;
    enc.map_text(&state.environment)?;
    enc.u64(
        u64::try_from(state.replay_entries.len())
            .map_err(|_| AdapterError::new(AdapterErrorCode::ResourceLimit))?,
    )?;
    for entry in &state.replay_entries {
        encode_replay_entry(&mut enc, types, schema_epoch, entry)?;
    }
    enc.u64(state.replay_cursor)?;
    enc.u64(state.call_count)?;
    enc.u64(state.action_count)?;
    Ok(enc.out)
}

fn validate_boundary(
    import: &AdapterImport,
    effect: &EffectDefinition,
    invocation: &AdapterInvocation,
) -> Result<()> {
    if import.adapter_id != invocation.kind.reference_id().into_bytes() {
        return fail(AdapterErrorCode::IdentityMismatch);
    }
    if import.abi_version != 1 {
        return fail(AdapterErrorCode::AbiMismatch);
    }
    if import.effects.as_slice() != [effect.entity_id]
        || effect.effect_kind != EffectKind::AdapterCall
    {
        return fail(AdapterErrorCode::EffectMismatch);
    }
    validate_concrete_types(invocation.kind, effect)?;
    if invocation.scope.value_type != effect.scope_type
        || invocation.request.value_type != effect.request_type
    {
        return fail(AdapterErrorCode::TypeMismatch);
    }
    Ok(())
}

fn validate_upstream_types(
    import: &AdapterImport,
    effect: &EffectDefinition,
    types: &TypeEnvironment,
    invocation: &AdapterInvocation,
) -> Result<()> {
    types.check_constant(&invocation.scope)?;
    types.check_constant(&invocation.request)?;
    types.require_hashable(&invocation.scope.value_type)?;
    types.require_hashable(&invocation.request.value_type)?;
    types.require_hashable(&effect.response_type)?;
    types.require_hashable(&effect.failure_type)?;
    if import.request_type != effect.request_type
        || import.response_type != effect.response_type
        || import.failure_type != effect.failure_type
    {
        return fail(AdapterErrorCode::TypeMismatch);
    }
    Ok(())
}

fn validate_concrete_types(kind: ReferenceAdapterKind, effect: &EffectDefinition) -> Result<()> {
    let u32_type = TypeExpr::UInt(IntegerWidth::from_bits(32));
    let u64_type = TypeExpr::UInt(IntegerWidth::from_bits(64));
    let expected = match kind {
        ReferenceAdapterKind::Stdout | ReferenceAdapterKind::Stderr => {
            (TypeExpr::Unit, TypeExpr::Bytes, TypeExpr::Unit, u32_type)
        }
        ReferenceAdapterKind::VirtualFileRead => {
            (TypeExpr::Text, TypeExpr::Text, TypeExpr::Bytes, u32_type)
        }
        ReferenceAdapterKind::VirtualFileWrite => (
            TypeExpr::Text,
            TypeExpr::Tuple(vec![TypeExpr::Text, TypeExpr::Bytes]),
            TypeExpr::Unit,
            u32_type,
        ),
        ReferenceAdapterKind::Clock => (TypeExpr::Unit, TypeExpr::Unit, u64_type, u32_type),
        ReferenceAdapterKind::Random => {
            (TypeExpr::Unit, u32_type.clone(), TypeExpr::Bytes, u32_type)
        }
        ReferenceAdapterKind::Environment => (
            TypeExpr::Unit,
            TypeExpr::Text,
            TypeExpr::Option(Box::new(TypeExpr::Text)),
            u32_type,
        ),
        ReferenceAdapterKind::GenericReplay => return Ok(()),
    };
    if (
        effect.scope_type.clone(),
        effect.request_type.clone(),
        effect.response_type.clone(),
        effect.failure_type.clone(),
    ) == expected
    {
        Ok(())
    } else {
        fail(AdapterErrorCode::TypeMismatch)
    }
}

#[allow(clippy::too_many_lines)]
fn plan_handler(
    state: &mut AdapterFixtureState,
    import: &AdapterImport,
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    invocation: &AdapterInvocation,
    call_index: u64,
) -> Result<AdapterOutcome> {
    match invocation.kind {
        ReferenceAdapterKind::Stdout => {
            let bytes = bytes_data(&invocation.request)?;
            let total = captured_output_bytes(state)?
                .checked_add(u64_len(bytes.len())?)
                .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
            if total > invocation.limits.max_output_bytes {
                return fail(AdapterErrorCode::ResourceLimit);
            }
            charge(state, invocation.cancel_at_action, invocation.limits, 1)?;
            state.stdout.extend_from_slice(bytes);
            Ok(AdapterOutcome::Success(unit()))
        }
        ReferenceAdapterKind::Stderr => {
            let bytes = bytes_data(&invocation.request)?;
            let total = captured_output_bytes(state)?
                .checked_add(u64_len(bytes.len())?)
                .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
            if total > invocation.limits.max_output_bytes {
                return fail(AdapterErrorCode::ResourceLimit);
            }
            charge(state, invocation.cancel_at_action, invocation.limits, 1)?;
            state.stderr.extend_from_slice(bytes);
            Ok(AdapterOutcome::Success(unit()))
        }
        ReferenceAdapterKind::VirtualFileRead => {
            let path = canonical_key(
                text_data(&invocation.scope)?,
                text_data(&invocation.request)?,
            )?;
            charge(state, invocation.cancel_at_action, invocation.limits, 1)?;
            Ok(match state.virtual_files.get(&path) {
                Some(bytes) => AdapterOutcome::Success(bytes_value(bytes.clone())),
                None => AdapterOutcome::DeclaredFailure(u32_value(1)),
            })
        }
        ReferenceAdapterKind::VirtualFileWrite => {
            let (request_path, content) = tuple_text_bytes(&invocation.request)?;
            let path = canonical_key(text_data(&invocation.scope)?, request_path)?;
            check_file_write_limits(state, &path, content, invocation.limits)?;
            charge(state, invocation.cancel_at_action, invocation.limits, 1)?;
            state.virtual_files.insert(path, content.to_vec());
            Ok(AdapterOutcome::Success(unit()))
        }
        ReferenceAdapterKind::Clock => {
            charge(state, invocation.cancel_at_action, invocation.limits, 1)?;
            let cursor = usize::try_from(state.clock_cursor)
                .map_err(|_| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
            let Some(tick) = state.clock_ticks.get(cursor).copied() else {
                return Ok(AdapterOutcome::DeclaredFailure(u32_value(2)));
            };
            state.clock_cursor = state
                .clock_cursor
                .checked_add(1)
                .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
            Ok(AdapterOutcome::Success(u64_value(tick)))
        }
        ReferenceAdapterKind::Random => {
            let n = u64_from_u32_const(&invocation.request)?;
            if n > invocation.limits.max_random_bytes || n > MAX_BLOB {
                return fail(AdapterErrorCode::ResourceLimit);
            }
            let blocks = n.div_ceil(32);
            charge(state, invocation.cancel_at_action, invocation.limits, 1)?;
            let mut out = Vec::with_capacity(
                usize::try_from(n)
                    .map_err(|_| AdapterError::new(AdapterErrorCode::ResourceLimit))?,
            );
            for offset in 0..blocks {
                let counter = state
                    .random_counter
                    .checked_add(offset)
                    .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
                let block = random_block(state.random_seed, counter);
                let take = usize::try_from(
                    (n - u64::try_from(out.len())
                        .map_err(|_| AdapterError::new(AdapterErrorCode::ResourceLimit))?)
                    .min(32),
                )
                .map_err(|_| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
                out.extend_from_slice(&block[..take]);
            }
            state.random_counter = state
                .random_counter
                .checked_add(blocks)
                .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
            Ok(AdapterOutcome::Success(bytes_value(out)))
        }
        ReferenceAdapterKind::Environment => {
            let key = text_data(&invocation.request)?;
            charge(state, invocation.cancel_at_action, invocation.limits, 1)?;
            Ok(AdapterOutcome::Success(option_text(
                state.environment.get(key).cloned(),
            )))
        }
        ReferenceAdapterKind::GenericReplay => {
            charge(state, invocation.cancel_at_action, invocation.limits, 1)?;
            let index = usize::try_from(state.replay_cursor)
                .map_err(|_| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
            let Some(entry) = state.replay_entries.get(index) else {
                return fail(AdapterErrorCode::ReplayExhausted);
            };
            let scope_hash = hash_const(types, schema_epoch, &invocation.scope)?;
            let request_hash = hash_const(types, schema_epoch, &invocation.request)?;
            if entry.import_id != import.entity_id
                || entry.adapter_id != import.adapter_id
                || entry.abi_version != import.abi_version
                || entry.call_index != call_index
                || entry.scope_hash != scope_hash
                || entry.request_hash != request_hash
            {
                return fail(AdapterErrorCode::ReplayMismatch);
            }
            state.replay_cursor = state
                .replay_cursor
                .checked_add(1)
                .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
            Ok(entry.outcome.clone())
        }
    }
}

struct TranscriptInput<'a> {
    types: &'a TypeEnvironment,
    schema_epoch: SchemaEpochId,
    root: StateRoot,
    import: &'a AdapterImport,
    effect: &'a EffectDefinition,
    invocation: &'a AdapterInvocation,
    call_index: u64,
    pre_state: AdapterStateId,
    post_state: AdapterStateId,
    outcome: &'a AdapterOutcome,
    actions_used: u64,
    output_bytes: u64,
    max_preimage_bytes: u64,
}

fn validate_outcome(
    types: &TypeEnvironment,
    effect: &EffectDefinition,
    outcome: &AdapterOutcome,
) -> Result<()> {
    let (value, expected_type) = match outcome {
        AdapterOutcome::Success(value) => (value, &effect.response_type),
        AdapterOutcome::DeclaredFailure(value) => (value, &effect.failure_type),
    };
    types.check_constant(value)?;
    types.require_hashable(&value.value_type)?;
    if &value.value_type == expected_type {
        Ok(())
    } else {
        fail(AdapterErrorCode::TypeMismatch)
    }
}

fn preflight_state(state: &AdapterFixtureState, limits: AdapterLimits) -> Result<()> {
    validate_limits(limits)?;
    if u64_len(state.virtual_files.len())? > MAX_FILES
        || u64_len(state.virtual_files.len())? > limits.max_virtual_files
        || u64_len(state.environment.len())? > MAX_ENV
        || u64_len(state.replay_entries.len())? > MAX_REPLAY
        || u64_len(state.clock_ticks.len())? > MAX_TICKS
    {
        return fail(AdapterErrorCode::ResourceLimit);
    }
    let total_files = total_virtual_file_bytes(state)?;
    if total_files > limits.max_total_virtual_file_bytes
        || captured_output_bytes(state)? > limits.max_output_bytes
    {
        return fail(AdapterErrorCode::ResourceLimit);
    }
    if state.virtual_files.values().any(|value| {
        u64_len(value.len()).is_ok_and(|len| len > limits.max_virtual_file_bytes || len > MAX_BLOB)
    }) {
        return fail(AdapterErrorCode::ResourceLimit);
    }
    Ok(())
}

fn validate_limits(limits: AdapterLimits) -> Result<()> {
    if limits.max_output_bytes > MAX_PREIMAGE
        || limits.max_virtual_files > MAX_FILES
        || limits.max_virtual_file_bytes > MAX_BLOB
        || limits.max_total_virtual_file_bytes > MAX_PREIMAGE
        || limits.max_random_bytes > MAX_BLOB
        || limits.max_state_preimage_bytes > MAX_PREIMAGE
        || limits.max_transcript_preimage_bytes > MAX_PREIMAGE
    {
        fail(AdapterErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn validate_state(state: &AdapterFixtureState) -> Result<()> {
    if state.clock_cursor > u64_len(state.clock_ticks.len())?
        || state.replay_cursor > u64_len(state.replay_entries.len())?
    {
        return fail(AdapterErrorCode::StateInvalid);
    }
    for path in state.virtual_files.keys() {
        validate_full_path(path)?;
    }
    for key in state.environment.keys() {
        if key.is_empty()
            || key.len() > 4_096
            || key.bytes().any(|byte| byte == 0 || byte.is_ascii_control())
        {
            return fail(AdapterErrorCode::StateInvalid);
        }
    }
    Ok(())
}

fn validate_full_path(path: &str) -> Result<()> {
    let Some((scope, request)) = path.split_once('/') else {
        return fail(AdapterErrorCode::StateInvalid);
    };
    Ok(canonical_key(scope, request)
        .map(|_| ())
        .map_err(|_| AdapterError::new(AdapterErrorCode::StateInvalid))?)
}

fn canonical_key(scope: &str, request: &str) -> Result<String> {
    validate_component(scope).map_err(|_| AdapterError::new(AdapterErrorCode::PathInvalid))?;
    if request.is_empty()
        || request.len() > MAX_REQUEST_PATH_BYTES
        || request.starts_with('/')
        || request.ends_with('/')
        || request.contains('\\')
        || request.contains('%')
        || request
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control() || !byte.is_ascii())
    {
        return fail(AdapterErrorCode::PathInvalid);
    }
    let mut count = 0_u32;
    for component in request.split('/') {
        count += 1;
        if count > 32 {
            return fail(AdapterErrorCode::PathInvalid);
        }
        validate_component(component)
            .map_err(|_| AdapterError::new(AdapterErrorCode::PathInvalid))?;
    }
    Ok(format!("{scope}/{request}"))
}

fn validate_component(component: &str) -> Result<()> {
    if component.is_empty()
        || component.len() > MAX_PATH_COMPONENT_BYTES
        || matches!(component, "." | "..")
    {
        return fail(AdapterErrorCode::PathInvalid);
    }
    let mut bytes = component.bytes();
    let Some(first) = bytes.next() else {
        return fail(AdapterErrorCode::PathInvalid);
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return fail(AdapterErrorCode::PathInvalid);
    }
    if bytes.any(|byte| {
        !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-'))
    }) {
        return fail(AdapterErrorCode::PathInvalid);
    }
    Ok(())
}

fn check_file_write_limits(
    state: &AdapterFixtureState,
    path: &str,
    content: &[u8],
    limits: AdapterLimits,
) -> Result<()> {
    let content_len = u64_len(content.len())?;
    if content_len > limits.max_virtual_file_bytes || content_len > MAX_BLOB {
        return fail(AdapterErrorCode::ResourceLimit);
    }
    let new_file = !state.virtual_files.contains_key(path);
    let file_count = u64_len(state.virtual_files.len())? + u64::from(new_file);
    if file_count > limits.max_virtual_files || file_count > MAX_FILES {
        return fail(AdapterErrorCode::ResourceLimit);
    }
    let previous = state
        .virtual_files
        .get(path)
        .map_or(Ok(0), |value| u64_len(value.len()))?;
    let total = total_virtual_file_bytes(state)?
        .checked_sub(previous)
        .and_then(|value| value.checked_add(content_len))
        .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
    if total > limits.max_total_virtual_file_bytes || total > MAX_PREIMAGE {
        return fail(AdapterErrorCode::ResourceLimit);
    }
    Ok(())
}

fn charge(
    state: &mut AdapterFixtureState,
    cancel_at_action: Option<u64>,
    limits: AdapterLimits,
    amount: u64,
) -> Result<()> {
    for _ in 0..amount {
        charge_cancel(state, cancel_at_action, 0)?;
        let next = state
            .action_count
            .checked_add(1)
            .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
        if next > limits.max_actions {
            return fail(AdapterErrorCode::ResourceLimit);
        }
        state.action_count = next;
    }
    Ok(())
}

fn charge_cancel(
    state: &AdapterFixtureState,
    cancel_at_action: Option<u64>,
    _amount: u64,
) -> Result<()> {
    if cancel_at_action.is_some_and(|limit| limit <= state.action_count) {
        fail(AdapterErrorCode::Cancelled)
    } else {
        Ok(())
    }
}

fn transcript_id(input: &TranscriptInput<'_>) -> Result<AdapterTranscriptId> {
    Ok(AdapterTranscriptId::derive(transcript_preimage(input)?))
}

fn transcript_preimage(input: &TranscriptInput<'_>) -> Result<Vec<u8>> {
    let mut enc = Encoder::new(input.max_preimage_bytes);
    enc.fixed(b"SLEYADT1")?;
    enc.u32(PROFILE_VERSION)?;
    enc.fixed(input.schema_epoch.as_bytes())?;
    enc.fixed(input.root.as_bytes())?;
    enc.fixed(input.import.entity_id.as_bytes())?;
    enc.fixed(input.effect.entity_id.as_bytes())?;
    enc.fixed(&input.import.adapter_id)?;
    enc.u32(input.import.abi_version)?;
    enc.u32(input.invocation.kind.tag())?;
    enc.u64(input.call_index)?;
    enc.fixed(hash_const(input.types, input.schema_epoch, &input.invocation.scope)?.as_bytes())?;
    enc.fixed(hash_const(input.types, input.schema_epoch, &input.invocation.request)?.as_bytes())?;
    enc.fixed(input.pre_state.as_bytes())?;
    enc.fixed(input.post_state.as_bytes())?;
    encode_outcome_hash(&mut enc, input.types, input.schema_epoch, input.outcome)?;
    enc.u64(input.actions_used)?;
    enc.u64(input.output_bytes)?;
    Ok(enc.out)
}

fn encode_replay_entry(
    enc: &mut Encoder,
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    entry: &ReplayEntry,
) -> Result<()> {
    enc.fixed(entry.import_id.as_bytes())?;
    enc.fixed(&entry.adapter_id)?;
    enc.u32(entry.abi_version)?;
    enc.u64(entry.call_index)?;
    enc.fixed(entry.scope_hash.as_bytes())?;
    enc.fixed(entry.request_hash.as_bytes())?;
    encode_outcome_hash(enc, types, schema_epoch, &entry.outcome)
}

fn encode_outcome_hash(
    enc: &mut Encoder,
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    outcome: &AdapterOutcome,
) -> Result<()> {
    match outcome {
        AdapterOutcome::Success(value) => {
            enc.u32(1)?;
            enc.fixed(hash_const(types, schema_epoch, value)?.as_bytes())
        }
        AdapterOutcome::DeclaredFailure(value) => {
            enc.u32(2)?;
            enc.fixed(hash_const(types, schema_epoch, value)?.as_bytes())
        }
    }
}

fn hash_const(
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    value: &ConstValue,
) -> Result<ValueHash> {
    types.check_constant(value)?;
    types.require_hashable(&value.value_type)?;
    Ok(hash_validated_value(schema_epoch, value)?)
}

fn random_block(seed: [u8; 32], counter: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sley2.reference-random.v1");
    hasher.update(&seed);
    hasher.update(&counter.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn captured_output_bytes(state: &AdapterFixtureState) -> Result<u64> {
    Ok(u64_len(state.stdout.len())?
        .checked_add(u64_len(state.stderr.len())?)
        .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))?)
}

fn total_virtual_file_bytes(state: &AdapterFixtureState) -> Result<u64> {
    Ok(state
        .virtual_files
        .values()
        .try_fold(0_u64, |total, bytes| {
            let len = u64::try_from(bytes.len())
                .map_err(|_| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
            total
                .checked_add(len)
                .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))
        })?)
}

fn unit() -> ConstValue {
    ConstValue {
        value_type: TypeExpr::Unit,
        data: ConstData::Unit,
    }
}

fn bytes_value(bytes: Vec<u8>) -> ConstValue {
    ConstValue {
        value_type: TypeExpr::Bytes,
        data: ConstData::Bytes(bytes),
    }
}

fn u32_value(value: u32) -> ConstValue {
    ConstValue {
        value_type: TypeExpr::UInt(IntegerWidth::from_bits(32)),
        data: ConstData::UInt(u128::from(value)),
    }
}

fn u64_value(value: u64) -> ConstValue {
    ConstValue {
        value_type: TypeExpr::UInt(IntegerWidth::from_bits(64)),
        data: ConstData::UInt(u128::from(value)),
    }
}

fn option_text(value: Option<String>) -> ConstValue {
    ConstValue {
        value_type: TypeExpr::Option(Box::new(TypeExpr::Text)),
        data: ConstData::Option(value.map(|text| {
            Box::new(ConstValue {
                value_type: TypeExpr::Text,
                data: ConstData::Text(text),
            })
        })),
    }
}

fn text_data(value: &ConstValue) -> Result<&str> {
    match &value.data {
        ConstData::Text(text) => Ok(text),
        _ => fail(AdapterErrorCode::TypeMismatch),
    }
}

fn bytes_data(value: &ConstValue) -> Result<&[u8]> {
    match &value.data {
        ConstData::Bytes(bytes) => Ok(bytes),
        _ => fail(AdapterErrorCode::TypeMismatch),
    }
}

fn tuple_text_bytes(value: &ConstValue) -> Result<(&str, &[u8])> {
    match &value.data {
        ConstData::Sequence(items) if items.len() == 2 => {
            Ok((text_data(&items[0])?, bytes_data(&items[1])?))
        }
        _ => fail(AdapterErrorCode::TypeMismatch),
    }
}

fn u64_from_u32_const(value: &ConstValue) -> Result<u64> {
    match value.data {
        ConstData::UInt(number) if number <= u128::from(u32::MAX) => {
            Ok(u64::try_from(number)
                .map_err(|_| AdapterError::new(AdapterErrorCode::TypeMismatch))?)
        }
        _ => fail(AdapterErrorCode::TypeMismatch),
    }
}

fn u64_len(len: usize) -> Result<u64> {
    Ok(u64::try_from(len).map_err(|_| AdapterError::new(AdapterErrorCode::ResourceLimit))?)
}

fn fail<T>(code: AdapterErrorCode) -> Result<T> {
    Err(AdapterError::new(code).into())
}

struct Encoder {
    out: Vec<u8>,
    max: u64,
}

impl Encoder {
    fn new(max: u64) -> Self {
        Self {
            out: Vec::new(),
            max,
        }
    }

    fn ensure(&self, len: usize) -> Result<()> {
        let next = u64_len(self.out.len())?
            .checked_add(u64_len(len)?)
            .ok_or_else(|| AdapterError::new(AdapterErrorCode::ResourceLimit))?;
        if next > self.max {
            fail(AdapterErrorCode::ResourceLimit)
        } else {
            Ok(())
        }
    }

    fn fixed(&mut self, bytes: &[u8]) -> Result<()> {
        self.ensure(bytes.len())?;
        self.out.extend_from_slice(bytes);
        Ok(())
    }

    fn u32(&mut self, value: u32) -> Result<()> {
        self.fixed(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<()> {
        self.fixed(&value.to_be_bytes())
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.u64(u64_len(bytes.len())?)?;
        self.fixed(bytes)
    }

    fn text(&mut self, value: &str) -> Result<()> {
        self.bytes(value.as_bytes())
    }

    fn map_bytes(&mut self, map: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        self.u64(u64_len(map.len())?)?;
        for (key, value) in map {
            self.text(key)?;
            self.bytes(value)?;
        }
        Ok(())
    }

    fn map_text(&mut self, map: &BTreeMap<String, String>) -> Result<()> {
        self.u64(u64_len(map.len())?)?;
        for (key, value) in map {
            self.text(key)?;
            self.text(value)?;
        }
        Ok(())
    }

    fn u64_list(&mut self, items: &[u64]) -> Result<()> {
        self.u64(u64_len(items.len())?)?;
        for item in items {
            self.u64(*item)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sley_id::WorkspaceId;
    use sley_policy::{
        CapabilityIssuerId, CapabilityKeyId, CapabilitySecret, CapabilityTokenNonce,
        CapabilityTokenRequest, PolicyResourceCeilings, PolicyRootBuilder, PrincipalGrantBuilder,
        conformance_registry as policy_registry, issue_capability_token,
    };
    use sley_ssmc::Visibility;

    fn eid(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    fn workspace() -> WorkspaceId {
        WorkspaceId::from_bytes([1; 32])
    }

    fn principal() -> PrincipalId {
        PrincipalId::from_bytes([3; 32])
    }

    fn epoch() -> SchemaEpochId {
        SchemaEpochId::from_bytes([9; 32])
    }

    fn root() -> StateRoot {
        StateRoot::from_bytes([7; 32])
    }

    fn types() -> TypeEnvironment {
        TypeEnvironment::new(Vec::new()).unwrap()
    }

    fn effect(kind: ReferenceAdapterKind) -> EffectDefinition {
        let u32_type = TypeExpr::UInt(IntegerWidth::from_bits(32));
        let u64_type = TypeExpr::UInt(IntegerWidth::from_bits(64));
        let (scope_type, request_type, response_type, failure_type) = match kind {
            ReferenceAdapterKind::Stdout | ReferenceAdapterKind::Stderr => {
                (TypeExpr::Unit, TypeExpr::Bytes, TypeExpr::Unit, u32_type)
            }
            ReferenceAdapterKind::VirtualFileRead => {
                (TypeExpr::Text, TypeExpr::Text, TypeExpr::Bytes, u32_type)
            }
            ReferenceAdapterKind::VirtualFileWrite => (
                TypeExpr::Text,
                TypeExpr::Tuple(vec![TypeExpr::Text, TypeExpr::Bytes]),
                TypeExpr::Unit,
                u32_type,
            ),
            ReferenceAdapterKind::Clock => (TypeExpr::Unit, TypeExpr::Unit, u64_type, u32_type),
            ReferenceAdapterKind::Random => {
                (TypeExpr::Unit, u32_type.clone(), TypeExpr::Bytes, u32_type)
            }
            ReferenceAdapterKind::Environment => (
                TypeExpr::Unit,
                TypeExpr::Text,
                TypeExpr::Option(Box::new(TypeExpr::Text)),
                u32_type,
            ),
            ReferenceAdapterKind::GenericReplay => {
                (TypeExpr::Unit, TypeExpr::Bytes, TypeExpr::Bytes, u32_type)
            }
        };
        EffectDefinition {
            entity_id: eid(u8::try_from(kind.tag()).unwrap()),
            effect_kind: EffectKind::AdapterCall,
            scope_type,
            request_type,
            response_type,
            failure_type,
            visibility: Visibility::Private,
        }
    }

    fn import(kind: ReferenceAdapterKind, effect: &EffectDefinition) -> AdapterImport {
        AdapterImport {
            entity_id: eid(99),
            adapter_id: kind.reference_id().into_bytes(),
            abi_version: 1,
            request_type: effect.request_type.clone(),
            response_type: effect.response_type.clone(),
            failure_type: effect.failure_type.clone(),
            effects: vec![effect.entity_id],
        }
    }

    fn trusted_key() -> CapabilityTrustedKey {
        CapabilityTrustedKey::new(
            CapabilityIssuerId::from_bytes([10; 32]),
            CapabilityKeyId::from_bytes([11; 32]),
            CapabilitySecret::from_bytes([12; 32]),
        )
    }

    fn authorized_limits() -> AdapterLimits {
        AdapterLimits {
            max_calls: 16,
            max_actions: 10_000,
            max_output_bytes: 1_048_576,
            max_virtual_files: 100,
            max_virtual_file_bytes: 1_048_576,
            max_total_virtual_file_bytes: 4_194_304,
            max_random_bytes: 1_048_576,
            max_state_preimage_bytes: 8_388_608,
            max_transcript_preimage_bytes: 8_388_608,
        }
    }

    fn authorized_token_budget() -> CapabilityResourceBudget {
        let one = capability_budget_for_adapter_limits(authorized_limits()).unwrap();
        CapabilityResourceBudget::new(
            one.max_fuel * 2,
            one.max_memory_bytes * 2,
            one.max_output_bytes * 2,
            one.max_effect_count * 2,
            0,
            one.max_adapter_calls * 2,
        )
    }

    fn policy_for(adapter_id: ReferenceAdapterId) -> AcceptedPolicyRoot {
        let budget = authorized_token_budget();
        let grant = PrincipalGrantBuilder::new(PolicyResourceCeilings::new(
            budget.max_fuel,
            budget.max_memory_bytes,
            budget.max_output_bytes,
            budget.max_effect_count,
            budget.max_mutation_count,
            budget.max_adapter_calls,
        ))
        .effect_kind(EffectKind::AdapterCall)
        .adapter_id(adapter_id)
        .build()
        .unwrap();
        PolicyRootBuilder::new(workspace())
            .principal_grant(principal(), grant)
            .build(&policy_registry().unwrap())
            .unwrap()
    }

    fn token_for(
        policy: &AcceptedPolicyRoot,
        adapter_id: ReferenceAdapterId,
        effect_id: EntityId,
        scope_hash: ValueHash,
    ) -> CapabilityToken {
        token_for_budget(
            policy,
            adapter_id,
            effect_id,
            scope_hash,
            authorized_token_budget(),
        )
    }

    fn token_for_budget(
        policy: &AcceptedPolicyRoot,
        adapter_id: ReferenceAdapterId,
        effect_id: EntityId,
        scope_hash: ValueHash,
        budget: CapabilityResourceBudget,
    ) -> CapabilityToken {
        issue_capability_token(
            policy,
            &trusted_key(),
            &CapabilityTokenRequest {
                principal_id: principal(),
                workspace_id: workspace(),
                state_root: root(),
                effect_id,
                effect_kind: EffectKind::AdapterCall,
                scope_hash,
                adapter_id,
                budget,
                now_unix_millis: 100,
                expiry_unix_millis: 200,
                token_nonce: CapabilityTokenNonce::from_bytes([13; 32]),
            },
        )
        .unwrap()
    }

    fn invocation(
        kind: ReferenceAdapterKind,
        scope: ConstValue,
        request: ConstValue,
    ) -> AdapterInvocation {
        AdapterInvocation {
            kind,
            scope,
            request,
            limits: AdapterLimits::profile_max(),
            cancel_at_action: None,
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn call(
        state: &mut AdapterFixtureState,
        invocation: AdapterInvocation,
    ) -> Result<AdapterReceipt> {
        let effect = effect(invocation.kind);
        let import = import(invocation.kind, &effect);
        invoke_reference_adapter(
            state,
            &import,
            &effect,
            &types(),
            epoch(),
            root(),
            &invocation,
        )
    }

    fn authorization<'a>(
        policy: &'a AcceptedPolicyRoot,
        token: &'a CapabilityToken,
        trusted_key: &'a CapabilityTrustedKey,
        ledger: &'a mut CapabilityLedger,
        use_nonce: u8,
    ) -> AdapterAuthorization<'a> {
        AdapterAuthorization {
            policy,
            token,
            trusted_key,
            ledger,
            principal_id: principal(),
            now_unix_millis: 150,
            use_nonce: CapabilityUseNonce::from_bytes([use_nonce; 32]),
        }
    }

    fn unit_value() -> ConstValue {
        unit()
    }

    fn text_value(value: &str) -> ConstValue {
        ConstValue {
            value_type: TypeExpr::Text,
            data: ConstData::Text(value.to_owned()),
        }
    }

    fn tuple_value(path: &str, bytes: &[u8]) -> ConstValue {
        ConstValue {
            value_type: TypeExpr::Tuple(vec![TypeExpr::Text, TypeExpr::Bytes]),
            data: ConstData::Sequence(vec![text_value(path), bytes_value(bytes.to_vec())]),
        }
    }

    #[test]
    fn fixed_reference_ids_cover_all_kinds() {
        let ids = [
            ReferenceAdapterKind::Stdout.reference_id(),
            ReferenceAdapterKind::Stderr.reference_id(),
            ReferenceAdapterKind::VirtualFileRead.reference_id(),
            ReferenceAdapterKind::VirtualFileWrite.reference_id(),
            ReferenceAdapterKind::Clock.reference_id(),
            ReferenceAdapterKind::Random.reference_id(),
            ReferenceAdapterKind::Environment.reference_id(),
            ReferenceAdapterKind::GenericReplay.reference_id(),
        ];
        assert_eq!(ids.len(), 8);
        for (left_index, left) in ids.iter().enumerate() {
            for right in &ids[left_index + 1..] {
                assert_ne!(left, right);
            }
        }
        let expected = [
            "3fed53d3fb5f19f96faa65ab0cc893807a080dd8ff5df7f87cf344d7e50fc422",
            "4aa8cf7e0ce6174971017db213009d223f6f9b8a2666117f767139f05a1baedb",
            "e2352120a6e7c2b0d8a731578f7ec2924f7efd0fdbb183aa1eb306c18da20855",
            "362f20dcd0aa9a8260b604992e9bb1ab41f8643cccc60ce7aa6e71b78c9ba466",
            "a52f0f592b0b62d7e22ae8a42986a4ecc2a7f87265eff65df1b3118355ece17b",
            "f6eceda6b7dc6ef2cca49a0aac30c058b1bf4dd3746b6a40e794ee0737f8779c",
            "dd58b70e61d83b6b71a1ddd8f9b796ba0a9d32fb27a6ce60a229fccf5a97d211",
            "823d57c133fceafb01a49ae0a77b94724a231748f1098ff7ee83cdf2cc6ad074",
        ];
        for (id, expected_hex) in ids.into_iter().zip(expected) {
            assert_eq!(id.into_bytes(), decode_hex_32(expected_hex));
        }
    }

    #[test]
    fn fixed_state_and_transcript_vectors() {
        let mut state = AdapterFixtureState::default();
        let state_preimage = state_preimage(&state, &types(), epoch(), MAX_PREIMAGE).unwrap();
        let state_digest = state_id(&state, &types(), epoch(), MAX_PREIMAGE).unwrap();
        let mut expected_state_preimage = b"SLEYADS1".to_vec();
        expected_state_preimage.extend_from_slice(&1_u32.to_be_bytes());
        for _ in 0..5 {
            expected_state_preimage.extend_from_slice(&0_u64.to_be_bytes());
        }
        expected_state_preimage.extend_from_slice(&[0; 32]);
        for _ in 0..6 {
            expected_state_preimage.extend_from_slice(&0_u64.to_be_bytes());
        }
        assert_eq!(state_preimage, expected_state_preimage);
        assert_eq!(state_preimage.len(), 132);
        assert_eq!(
            state_digest.into_bytes(),
            decode_hex_32("36fb468aef439f2a25dba8b62274a5ebdc99dad0dcba0a3eb1caaf3abea6a633")
        );

        let kind = ReferenceAdapterKind::Stdout;
        let effect = effect(kind);
        let import = import(kind, &effect);
        let invocation = invocation(kind, unit_value(), bytes_value(b"vector".to_vec()));
        let receipt = invoke_reference_adapter(
            &mut state,
            &import,
            &effect,
            &types(),
            epoch(),
            root(),
            &invocation,
        )
        .unwrap();
        let transcript_preimage = transcript_preimage(&TranscriptInput {
            types: &types(),
            schema_epoch: epoch(),
            root: root(),
            import: &import,
            effect: &effect,
            invocation: &invocation,
            call_index: receipt.call_index,
            pre_state: receipt.pre_state,
            post_state: receipt.post_state,
            outcome: &receipt.outcome,
            actions_used: receipt.actions_used,
            output_bytes: receipt.output_bytes,
            max_preimage_bytes: MAX_PREIMAGE,
        })
        .unwrap();
        assert_eq!(transcript_preimage.len(), 368);
        assert_eq!(&transcript_preimage[..12], b"SLEYADT1\0\0\0\x01");
        assert_eq!(
            receipt.post_state.into_bytes(),
            decode_hex_32("0302df2282b674624f032e6d63df6ab0f9bbcbd44ff052d71f5ac1940c342389")
        );
        assert_eq!(
            receipt.transcript.into_bytes(),
            decode_hex_32("08c1516430b53fdc9f61feb6d9338822be568c0c012ad45aaf6c3443c3dd230a")
        );
    }

    #[test]
    fn stdout_stderr_clock_random_environment_and_files_work() {
        let mut state = AdapterFixtureState {
            clock_ticks: vec![11],
            random_seed: [3; 32],
            environment: BTreeMap::from([("key".to_owned(), "value".to_owned())]),
            ..AdapterFixtureState::default()
        };

        let stdout = call(
            &mut state,
            invocation(
                ReferenceAdapterKind::Stdout,
                unit_value(),
                bytes_value(b"out".to_vec()),
            ),
        )
        .unwrap();
        assert_eq!(stdout.outcome, AdapterOutcome::Success(unit()));
        assert_eq!(state.stdout, b"out");

        call(
            &mut state,
            invocation(
                ReferenceAdapterKind::Stderr,
                unit_value(),
                bytes_value(b"err".to_vec()),
            ),
        )
        .unwrap();
        assert_eq!(state.stderr, b"err");

        call(
            &mut state,
            invocation(
                ReferenceAdapterKind::VirtualFileWrite,
                text_value("root"),
                tuple_value("dir/file-1", b"body"),
            ),
        )
        .unwrap();
        let read = call(
            &mut state,
            invocation(
                ReferenceAdapterKind::VirtualFileRead,
                text_value("root"),
                text_value("dir/file-1"),
            ),
        )
        .unwrap();
        assert_eq!(
            read.outcome,
            AdapterOutcome::Success(bytes_value(b"body".to_vec()))
        );

        let clock = call(
            &mut state,
            invocation(ReferenceAdapterKind::Clock, unit_value(), unit_value()),
        )
        .unwrap();
        assert_eq!(clock.outcome, AdapterOutcome::Success(u64_value(11)));

        let random = call(
            &mut state,
            invocation(ReferenceAdapterKind::Random, unit_value(), u32_value(40)),
        )
        .unwrap();
        let AdapterOutcome::Success(random_value) = random.outcome else {
            panic!("random should succeed");
        };
        assert_eq!(bytes_data(&random_value).unwrap().len(), 40);
        assert_eq!(state.random_counter, 2);

        let env = call(
            &mut state,
            invocation(
                ReferenceAdapterKind::Environment,
                unit_value(),
                text_value("key"),
            ),
        )
        .unwrap();
        assert_eq!(
            env.outcome,
            AdapterOutcome::Success(option_text(Some("value".to_owned())))
        );
    }

    #[test]
    fn failures_do_not_mutate_state() {
        let mut state = AdapterFixtureState::default();
        let before = state.clone();
        let err = call(
            &mut state,
            invocation(
                ReferenceAdapterKind::VirtualFileRead,
                text_value("root"),
                text_value("../bad"),
            ),
        )
        .unwrap_err();
        assert_eq!(err.adapter_code(), Some(AdapterErrorCode::PathInvalid));
        assert_eq!(state, before);

        let mut cancelled = invocation(
            ReferenceAdapterKind::Stdout,
            unit_value(),
            bytes_value(b"x".to_vec()),
        );
        cancelled.cancel_at_action = Some(0);
        let err = call(&mut state, cancelled).unwrap_err();
        assert_eq!(err.adapter_code(), Some(AdapterErrorCode::Cancelled));
        assert_eq!(state, before);

        let mut limited = invocation(ReferenceAdapterKind::Random, unit_value(), u32_value(2));
        limited.limits.max_random_bytes = 1;
        let err = call(&mut state, limited).unwrap_err();
        assert_eq!(err.adapter_code(), Some(AdapterErrorCode::ResourceLimit));
        assert_eq!(state, before);
    }

    #[test]
    fn prior_type_failure_is_preserved_before_adapter_preflight() {
        let kind = ReferenceAdapterKind::Stdout;
        let effect = effect(kind);
        let import = import(kind, &effect);
        let mut state = AdapterFixtureState::default();
        let malformed = ConstValue {
            value_type: TypeExpr::Bytes,
            data: ConstData::Text("not-bytes".to_owned()),
        };
        let mut inv = invocation(kind, unit_value(), malformed);
        inv.limits.max_state_preimage_bytes = 0;
        let error = invoke_reference_adapter(
            &mut state,
            &import,
            &effect,
            &types(),
            epoch(),
            root(),
            &inv,
        )
        .unwrap_err();
        let AdapterInvocationError::Type(error) = error else {
            panic!("exact type failure must be preserved");
        };
        assert_eq!(error.code(), sley_check::TypeErrorCode::ConstShape);
    }

    #[test]
    fn identity_abi_and_effect_swaps_fail_without_mutation() {
        let kind = ReferenceAdapterKind::Stdout;
        let effect = effect(kind);
        let base_import = import(kind, &effect);
        let invocation = invocation(kind, unit_value(), bytes_value(b"x".to_vec()));

        let mut cases = Vec::new();
        let mut wrong_id = base_import.clone();
        wrong_id.adapter_id = ReferenceAdapterKind::Stderr.reference_id().into_bytes();
        cases.push((wrong_id, effect.clone(), AdapterErrorCode::IdentityMismatch));
        let mut wrong_abi = base_import.clone();
        wrong_abi.abi_version = 2;
        cases.push((wrong_abi, effect.clone(), AdapterErrorCode::AbiMismatch));
        let mut wrong_effect = effect.clone();
        wrong_effect.effect_kind = EffectKind::StdoutWrite;
        cases.push((base_import, wrong_effect, AdapterErrorCode::EffectMismatch));

        for (import, effect, expected) in cases {
            let mut state = AdapterFixtureState::default();
            let before = state.clone();
            let error = invoke_reference_adapter(
                &mut state,
                &import,
                &effect,
                &types(),
                epoch(),
                root(),
                &invocation,
            )
            .unwrap_err();
            assert_eq!(error.adapter_code(), Some(expected));
            assert_eq!(state, before);
        }
    }

    #[test]
    fn random_counter_overflow_is_atomic() {
        let mut state = AdapterFixtureState {
            random_counter: u64::MAX,
            ..AdapterFixtureState::default()
        };
        let before = state.clone();
        let error = call(
            &mut state,
            invocation(ReferenceAdapterKind::Random, unit_value(), u32_value(1)),
        )
        .unwrap_err();
        assert_eq!(error.adapter_code(), Some(AdapterErrorCode::ResourceLimit));
        assert_eq!(state, before);
    }

    #[test]
    fn smaller_output_limit_rejects_preexisting_state_atomically() {
        let mut state = AdapterFixtureState {
            stdout: b"already".to_vec(),
            ..AdapterFixtureState::default()
        };
        let before = state.clone();
        let mut inv = invocation(
            ReferenceAdapterKind::Environment,
            unit_value(),
            text_value("missing"),
        );
        inv.limits.max_output_bytes = 6;
        let error = call(&mut state, inv).unwrap_err();
        assert_eq!(error.adapter_code(), Some(AdapterErrorCode::ResourceLimit));
        assert_eq!(state, before);
    }

    #[test]
    fn generic_replay_matches_and_exhausts() {
        let mut state = AdapterFixtureState::default();
        let effect = effect(ReferenceAdapterKind::GenericReplay);
        let import = import(ReferenceAdapterKind::GenericReplay, &effect);
        let scope = unit_value();
        let request = bytes_value(b"req".to_vec());
        state.replay_entries.push(ReplayEntry {
            import_id: import.entity_id,
            adapter_id: import.adapter_id,
            abi_version: 1,
            call_index: 0,
            scope_hash: hash_const(&types(), epoch(), &scope).unwrap(),
            request_hash: hash_const(&types(), epoch(), &request).unwrap(),
            outcome: AdapterOutcome::Success(bytes_value(b"ok".to_vec())),
        });

        let inv = invocation(ReferenceAdapterKind::GenericReplay, scope, request);
        let receipt = invoke_reference_adapter(
            &mut state,
            &import,
            &effect,
            &types(),
            epoch(),
            root(),
            &inv,
        )
        .unwrap();
        assert_eq!(
            receipt.outcome,
            AdapterOutcome::Success(bytes_value(b"ok".to_vec()))
        );
        assert_eq!(state.replay_cursor, 1);

        let before = state.clone();
        let err = invoke_reference_adapter(
            &mut state,
            &import,
            &effect,
            &types(),
            epoch(),
            root(),
            &inv,
        )
        .unwrap_err();
        assert_eq!(err.adapter_code(), Some(AdapterErrorCode::ReplayExhausted));
        assert_eq!(state, before);
    }

    #[test]
    fn replay_mismatch_and_response_injection_are_atomic() {
        let effect = effect(ReferenceAdapterKind::GenericReplay);
        let import = import(ReferenceAdapterKind::GenericReplay, &effect);
        let scope = unit_value();
        let request = bytes_value(b"req".to_vec());
        let base = ReplayEntry {
            import_id: import.entity_id,
            adapter_id: import.adapter_id,
            abi_version: 1,
            call_index: 0,
            scope_hash: hash_const(&types(), epoch(), &scope).unwrap(),
            request_hash: hash_const(&types(), epoch(), &request).unwrap(),
            outcome: AdapterOutcome::Success(bytes_value(b"ok".to_vec())),
        };
        let inv = invocation(ReferenceAdapterKind::GenericReplay, scope, request);

        let mut mismatch = AdapterFixtureState {
            replay_entries: vec![ReplayEntry {
                request_hash: ValueHash::from_bytes([8; 32]),
                ..base.clone()
            }],
            ..AdapterFixtureState::default()
        };
        let before = mismatch.clone();
        let error = invoke_reference_adapter(
            &mut mismatch,
            &import,
            &effect,
            &types(),
            epoch(),
            root(),
            &inv,
        )
        .unwrap_err();
        assert_eq!(error.adapter_code(), Some(AdapterErrorCode::ReplayMismatch));
        assert_eq!(mismatch, before);

        let mut injected = AdapterFixtureState {
            replay_entries: vec![ReplayEntry {
                outcome: AdapterOutcome::Success(u64_value(9)),
                ..base
            }],
            ..AdapterFixtureState::default()
        };
        let before = injected.clone();
        let error = invoke_reference_adapter(
            &mut injected,
            &import,
            &effect,
            &types(),
            epoch(),
            root(),
            &inv,
        )
        .unwrap_err();
        assert_eq!(error.adapter_code(), Some(AdapterErrorCode::TypeMismatch));
        assert_eq!(injected, before);
    }

    #[test]
    fn replay_outcomes_bind_state_id_to_schema_epoch() {
        let mut state = AdapterFixtureState::default();
        state.replay_entries.push(ReplayEntry {
            import_id: eid(1),
            adapter_id: [2; 32],
            abi_version: 1,
            call_index: 0,
            scope_hash: ValueHash::from_bytes([3; 32]),
            request_hash: ValueHash::from_bytes([4; 32]),
            outcome: AdapterOutcome::Success(bytes_value(b"epoch-bound".to_vec())),
        });
        let first = state_id(&state, &types(), epoch(), MAX_PREIMAGE).unwrap();
        let second = state_id(
            &state,
            &types(),
            SchemaEpochId::from_bytes([10; 32]),
            MAX_PREIMAGE,
        )
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn repeated_equal_invocations_are_deterministic() {
        let inv = invocation(
            ReferenceAdapterKind::Stdout,
            unit_value(),
            bytes_value(b"same".to_vec()),
        );
        let mut baseline = None;
        for _ in 0..128 {
            let mut state = AdapterFixtureState::default();
            let receipt = call(&mut state, inv.clone()).unwrap();
            let snapshot = (
                receipt.outcome,
                receipt.post_state,
                receipt.transcript,
                state,
            );
            if let Some(expected) = &baseline {
                assert_eq!(&snapshot, expected);
            } else {
                baseline = Some(snapshot);
            }
        }
    }

    #[test]
    fn adversarial_paths_fail() {
        for path in [
            "", "/a", "a/", "a//b", "A", ".", "..", "a\\b", "a%2fb", "é", "a/..",
        ] {
            let mut state = AdapterFixtureState::default();
            let before = state.clone();
            let err = call(
                &mut state,
                invocation(
                    ReferenceAdapterKind::VirtualFileRead,
                    text_value("root"),
                    text_value(path),
                ),
            )
            .unwrap_err();
            assert_eq!(
                err.adapter_code(),
                Some(AdapterErrorCode::PathInvalid),
                "{path}"
            );
            assert_eq!(state, before);
        }
    }

    #[test]
    fn capability_budget_reserves_the_maximum_canonical_path() {
        let scope = "a".repeat(MAX_PATH_COMPONENT_BYTES);
        let mut components = vec!["b".repeat(MAX_PATH_COMPONENT_BYTES); 15];
        components.push("c".repeat(254));
        components.push("d".to_owned());
        let request = components.join("/");
        assert_eq!(request.len(), MAX_REQUEST_PATH_BYTES);
        assert_eq!(
            canonical_key(&scope, &request).unwrap().len(),
            usize::try_from(MAX_CANONICAL_PATH_BYTES).unwrap()
        );

        let limits = AdapterLimits {
            max_calls: 1,
            max_actions: 1,
            max_output_bytes: 0,
            max_virtual_files: 1,
            max_virtual_file_bytes: 0,
            max_total_virtual_file_bytes: 0,
            max_random_bytes: 0,
            max_state_preimage_bytes: 0,
            max_transcript_preimage_bytes: 0,
        };
        let budget = capability_budget_for_adapter_limits(limits).unwrap();
        assert_eq!(
            budget.max_memory_bytes,
            MAX_CANONICAL_PATH_BYTES + ENCODED_FILE_ENTRY_OVERHEAD
        );
    }

    #[test]
    fn authorized_adapter_success_charges_once_then_mutates_fixture() {
        let kind = ReferenceAdapterKind::Stdout;
        let effect = effect(kind);
        let import = import(kind, &effect);
        let mut invocation = invocation(kind, unit_value(), bytes_value(b"auth".to_vec()));
        invocation.limits = authorized_limits();
        let scope_hash = hash_const(&types(), epoch(), &invocation.scope).unwrap();
        let policy = policy_for(kind.reference_id());
        let trusted_key = trusted_key();
        let token = token_for(&policy, kind.reference_id(), effect.entity_id, scope_hash);
        let mut ledger = CapabilityLedger::new();
        let mut state = AdapterFixtureState::default();

        let receipt = invoke_authorized_reference_adapter(
            &mut state,
            &import,
            &effect,
            &types(),
            epoch(),
            root(),
            &invocation,
            authorization(&policy, &token, &trusted_key, &mut ledger, 1),
        )
        .unwrap();

        assert_eq!(state.stdout, b"auth");
        assert_eq!(
            receipt.capability_receipt.charged,
            capability_budget_for_adapter_limits(authorized_limits()).unwrap()
        );
        assert_eq!(
            ledger.spent(token.digest()),
            capability_budget_for_adapter_limits(authorized_limits()).unwrap()
        );
    }

    #[test]
    fn authorized_adapter_failure_before_charge_mutates_neither_ledger_nor_fixture() {
        let kind = ReferenceAdapterKind::Stdout;
        let effect = effect(kind);
        let import = import(kind, &effect);
        let mut invocation = invocation(kind, unit_value(), bytes_value(b"auth".to_vec()));
        invocation.limits = authorized_limits();
        let policy = policy_for(kind.reference_id());
        let trusted_key = trusted_key();
        let token = token_for(
            &policy,
            kind.reference_id(),
            effect.entity_id,
            ValueHash::from_bytes([99; 32]),
        );
        let mut ledger = CapabilityLedger::new();
        let mut state = AdapterFixtureState::default();
        let before = state.clone();

        let error = invoke_authorized_reference_adapter(
            &mut state,
            &import,
            &effect,
            &types(),
            epoch(),
            root(),
            &invocation,
            authorization(&policy, &token, &trusted_key, &mut ledger, 1),
        )
        .unwrap_err();

        assert_eq!(
            error.capability_error().unwrap().code_str(),
            "CAP_SCOPE_MISMATCH"
        );
        assert_eq!(ledger, CapabilityLedger::new());
        assert_eq!(state, before);
    }

    #[test]
    fn authorized_adapter_request_binding_confusion_fails_before_charge() {
        #[derive(Clone, Copy)]
        enum BindingCase {
            StateRoot,
            Effect,
            Adapter,
        }

        for (case, expected_code) in [
            (BindingCase::StateRoot, "CAP_STATE_ROOT_MISMATCH"),
            (BindingCase::Effect, "CAP_EFFECT_MISMATCH"),
            (BindingCase::Adapter, "CAP_ADAPTER_MISMATCH"),
        ] {
            let kind = ReferenceAdapterKind::Stdout;
            let effect = effect(kind);
            let mut import = import(kind, &effect);
            let mut invocation = invocation(kind, unit_value(), bytes_value(b"auth".to_vec()));
            invocation.limits = authorized_limits();
            let scope_hash = hash_const(&types(), epoch(), &invocation.scope).unwrap();
            let policy = policy_for(kind.reference_id());
            let trusted_key = trusted_key();
            let token_effect_id = if matches!(case, BindingCase::Effect) {
                eid(200)
            } else {
                effect.entity_id
            };
            let token = token_for(&policy, kind.reference_id(), token_effect_id, scope_hash);
            let invocation_root = if matches!(case, BindingCase::StateRoot) {
                StateRoot::from_bytes([8; 32])
            } else {
                root()
            };
            if matches!(case, BindingCase::Adapter) {
                import.adapter_id = ReferenceAdapterKind::Stderr.reference_id().into_bytes();
            }
            let mut ledger = CapabilityLedger::new();
            let mut state = AdapterFixtureState::default();
            let before = state.clone();

            let error = invoke_authorized_reference_adapter(
                &mut state,
                &import,
                &effect,
                &types(),
                epoch(),
                invocation_root,
                &invocation,
                authorization(&policy, &token, &trusted_key, &mut ledger, 1),
            )
            .unwrap_err();

            let AuthorizedAdapterInvocationError::Capability(error) = error else {
                panic!("binding confusion must fail before adapter execution");
            };
            assert_eq!(error.code_str(), expected_code);
            assert_eq!(ledger, CapabilityLedger::new());
            assert_eq!(state, before);
        }
    }

    #[test]
    fn authorized_adapter_resource_dimensions_fail_closed_before_charge() {
        let kind = ReferenceAdapterKind::Stdout;
        let effect = effect(kind);
        let import = import(kind, &effect);
        let mut invocation = invocation(kind, unit_value(), bytes_value(b"auth".to_vec()));
        invocation.limits = authorized_limits();
        let required = capability_budget_for_adapter_limits(invocation.limits).unwrap();
        let scope_hash = hash_const(&types(), epoch(), &invocation.scope).unwrap();
        let policy = policy_for(kind.reference_id());
        let trusted_key = trusted_key();

        let mut cases = Vec::new();
        let mut fuel = required;
        fuel.max_fuel -= 1;
        cases.push(fuel);
        let mut memory = required;
        memory.max_memory_bytes -= 1;
        cases.push(memory);
        let mut output = required;
        output.max_output_bytes -= 1;
        cases.push(output);
        let mut effects = required;
        effects.max_effect_count = 0;
        cases.push(effects);
        let mut calls = required;
        calls.max_adapter_calls = 0;
        cases.push(calls);

        for budget in cases {
            let token = token_for_budget(
                &policy,
                kind.reference_id(),
                effect.entity_id,
                scope_hash,
                budget,
            );
            let mut ledger = CapabilityLedger::new();
            let mut state = AdapterFixtureState::default();
            let before = state.clone();
            let error = invoke_authorized_reference_adapter(
                &mut state,
                &import,
                &effect,
                &types(),
                epoch(),
                root(),
                &invocation,
                authorization(&policy, &token, &trusted_key, &mut ledger, 1),
            )
            .unwrap_err();
            assert_eq!(
                error.capability_error().unwrap().code_str(),
                "CAP_BUDGET_EXCEEDED"
            );
            assert_eq!(ledger, CapabilityLedger::new());
            assert_eq!(state, before);
        }
    }

    #[test]
    fn authorized_adapter_failure_after_charge_consumes_ledger_without_fixture_mutation() {
        let kind = ReferenceAdapterKind::Stdout;
        let effect = effect(kind);
        let mut import = import(kind, &effect);
        import.adapter_id = ReferenceAdapterKind::Stderr.reference_id().into_bytes();
        let mut invocation = invocation(kind, unit_value(), bytes_value(b"auth".to_vec()));
        invocation.limits = authorized_limits();
        let scope_hash = hash_const(&types(), epoch(), &invocation.scope).unwrap();
        let policy = policy_for(ReferenceAdapterKind::Stderr.reference_id());
        let trusted_key = trusted_key();
        let token = token_for(
            &policy,
            ReferenceAdapterKind::Stderr.reference_id(),
            effect.entity_id,
            scope_hash,
        );
        let mut ledger = CapabilityLedger::new();
        let mut state = AdapterFixtureState::default();
        let before = state.clone();

        let error = invoke_authorized_reference_adapter(
            &mut state,
            &import,
            &effect,
            &types(),
            epoch(),
            root(),
            &invocation,
            authorization(&policy, &token, &trusted_key, &mut ledger, 1),
        )
        .unwrap_err();

        let AuthorizedAdapterInvocationError::AdapterAfterAuthorization {
            charge_receipt,
            error,
        } = error
        else {
            panic!("fixture failure should occur after a successful charge");
        };
        assert_eq!(
            error.adapter_code(),
            Some(AdapterErrorCode::IdentityMismatch)
        );
        assert_eq!(
            charge_receipt.charged,
            capability_budget_for_adapter_limits(authorized_limits()).unwrap()
        );
        assert_eq!(
            ledger.spent(token.digest()),
            capability_budget_for_adapter_limits(authorized_limits()).unwrap()
        );
        assert_eq!(state, before);

        let replay_error = invoke_authorized_reference_adapter(
            &mut state,
            &import,
            &effect,
            &types(),
            epoch(),
            root(),
            &invocation,
            authorization(&policy, &token, &trusted_key, &mut ledger, 1),
        )
        .unwrap_err();
        assert_eq!(
            replay_error.capability_error().unwrap().code_str(),
            "CAP_REPLAY"
        );
        assert_eq!(state, before);
    }

    #[test]
    fn stable_error_codes_are_exact() {
        assert_eq!(AdapterErrorCode::ProfileUnsupported.code(), 28_000);
        assert_eq!(AdapterErrorCode::IdentityMismatch.code(), 28_001);
        assert_eq!(AdapterErrorCode::AbiMismatch.code(), 28_002);
        assert_eq!(AdapterErrorCode::EffectMismatch.code(), 28_003);
        assert_eq!(AdapterErrorCode::TypeMismatch.code(), 28_004);
        assert_eq!(AdapterErrorCode::StateInvalid.code(), 28_005);
        assert_eq!(AdapterErrorCode::PathInvalid.code(), 28_006);
        assert_eq!(AdapterErrorCode::ReplayMismatch.code(), 28_007);
        assert_eq!(AdapterErrorCode::ReplayExhausted.code(), 28_008);
        assert_eq!(AdapterErrorCode::ResourceLimit.code(), 28_009);
        assert_eq!(AdapterErrorCode::Cancelled.code(), 28_010);
        assert_eq!(AdapterErrorCode::InternalInvariant.code(), 28_011);
    }

    fn decode_hex_32(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut out = [0_u8; 32];
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            out[index] = u8::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }
}
