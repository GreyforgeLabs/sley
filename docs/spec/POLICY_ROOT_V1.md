# Protected Policy Root v1

Status: S20-370 normative protected-policy contract.

This profile freezes a separately content-addressed policy record, exact
principal-specific grant data, mandatory test/contract finalization, and a pure
ordinary-program isolation check. It does not issue or authenticate capability
tokens, authorize policy transitions, construct candidates, mutate state, or
commit transactions.

## 1. Authority boundary

An accepted policy root is data used by later judgment. Its digest proves exact
bytes, not that the caller possesses authority. `PrincipalId`, labels, prompts,
model output, documentation, repository metadata, adapter text, and caller
claims never grant authority.

The only frozen transition mode is:

```text
ExternalHigherAuthorityOnly = 1
```

The builder can construct immutable genesis/proposal records and may bind a
parent digest as lineage evidence. This crate has no API that authenticates,
installs, or approves a transition. S20-390 may not install a replacement until
a separately authenticated higher-authority contract exists; all policy
transitions remain unapproved until then.

## 2. Principal identity and grants

`PrincipalId` is an opaque, host-supplied `FixedBytes<32>` value. It has no hash
domain and no ambient text representation in the kernel.

Each principal maps to one exact grant:

| Tag | Field | Type |
|---:|---|---|
| 1 | allowed_effect_kind_tags | `CanonicalSet<UInt32>` |
| 2 | allowed_mutation_class_tags | `CanonicalSet<UInt32>` |
| 3 | allowed_adapter_ids | `CanonicalSet<ReferenceAdapterId>` |
| 4 | resource_ceilings | six-field record |

Effect tags are exactly SSMC1 `1..=8`; mutation tags are exactly S20-340
`1..=16`. The adapter set uses exact S20-280 identities. An absent principal
fails `POLICY_GRANT_DENIED`; an empty grant remains empty and confers nothing.
S20-370 exposes lookup metadata only. S20-380 owns authenticated token scope,
expiry/replay, budgets-in-use, and runtime enforcement.

The resource-ceiling record is:

| Tag | Field | Type |
|---:|---|---|
| 1 | max_fuel | `UInt64` |
| 2 | max_memory_bytes | `UInt64` |
| 3 | max_output_bytes | `UInt64` |
| 4 | max_effect_count | `UInt64` |
| 5 | max_mutation_count | `UInt64` |
| 6 | max_adapter_calls | `UInt64` |

Each literal is at most `1,000,000,000,000,000`. Zero means the grant allows
none of that resource; it is not unlimited.

## 3. Standalone envelope and identity

```text
format_version    = 1
contract_tag      = 370
contract_domain   = "sley2.policy-root.v1"
digest_domain_tag = 8
kind_tag          = 370
```

```text
envelope_preimage = "SLEYSCB1" || uvar(1) || uvar(370) ||
                    SchemaEpochId[32] || len(payload) || payload
PolicyRootId = BLAKE3-256("sley2.policy-root.v1" || envelope_preimage)
stored_bytes = envelope_preimage || PolicyRootId[32]
```

The trailer is outside its own preimage and no bytes follow it. Construction
and import require an exact immutable schema registry row and preserved decoder
for contract 370. The current registry is a nonzero conformance epoch, not the
final production epoch assembled from all contracts.

Descriptor evidence:

```text
field_schema_hash = 18c124c267de228e79936a01e589aedafe576b8d0fdf611f12d517f0378aa335
decoder_limits_hash = ca84d0b5c4911bff88c6f5ed7c93e8f1eb6ef16b9193f53020a5649c01306725
```

The exact ASCII preimages live as public constants in `sley-policy` and are
rehashed by the unit suite.

## 4. Payload record

All eleven fields are required. Options use SCB1 union tag `0` for `None` and
tag `1` for `Some`.

| Tag | Field | Type |
|---:|---|---|
| 1 | workspace_id | `WorkspaceId` |
| 2 | schema_epoch_id | `SchemaEpochId` |
| 3 | policy_schema_version | `UInt32`, exactly 1 |
| 4 | parent_policy | `Option<PolicyRootId>` |
| 5 | principal_grants | `CanonicalMap<PrincipalId, PrincipalGrant>` |
| 6 | protected_entities | `CanonicalSet<EntityId>` |
| 7 | required_tests | `CanonicalSet<EntityId>` |
| 8 | required_contracts | `CanonicalSet<EntityId>` |
| 9 | expiry_unix_millis | `Option<UInt64>` |
| 10 | transition_mode | `UInt32`, exactly 1 |
| 11 | interpretation_flags | `CanonicalSet<UInt32>`, empty in v1 |

`expiry_unix_millis` is bound data only. This crate never reads a clock or
decides whether it has passed. S20-380 must combine it with authenticated host
time and token rules.

## 5. Canonicality and limits

Construction sorts unordered semantic inputs and rejects duplicates. Strict
import never normalizes. Map/set order is full canonical encoded-byte order;
unknown tags, duplicates, nonminimal integers, missing/unknown/reordered fields,
epoch mismatch, digest mismatch, trailing bytes, and excessive allocations fail
closed.

| Collection | Maximum |
|---|---:|
| principal grants | 65,535 |
| effect or mutation tags per grant | 4,096 |
| adapters per grant | 65,535 |
| protected entities | 65,535 |
| required tests | 65,535 |
| required contracts | 65,535 |
| standalone bytes | 67,108,864 |

The fixed accepted vector has policy root
`7a933b888107588fd4cb942581e531f632a52dd15bb342145337b5ceac2907bf`.
The zero-epoch synthetic vector hashes to
`94d3887012304f42f581dac7516a3c3998b83210edf7cbdc8d31377fbde92ad4`
but fails registry authorization.

## 6. Ordinary-program isolation

The pure isolation validator requires the accepted policy digest to equal the
base `StateRoot.policy_root`, the policy/base/candidate workspace to agree, and
the candidate to preserve the base policy root, schema epoch, contract root,
test root, and every protected entity binding. The first mismatch fails in that
order. Missing protected bindings fail; deletion cannot evade comparison.

This is a pure structural S20-370 check over already accepted typed inputs. It
does not establish candidate authenticity or advance state. S20-360 must place
it in the complete monotonic validation pipeline, and S20-390 must recheck the
exact accepted base before commit.

## 7. Mandatory tests and contracts

The policy-aware finalizer accepts an accepted policy plus an S20-240
`PolicyIncomplete` report. It requires canonical report inventories, requires
every policy contract to appear in the validated contract inventory, and
requires every policy test to appear in both the validated and selected test
inventories. Success returns a distinct plan bound to the exact `PolicyRootId`.

The result is policy-final selection evidence only. S20-360 must prove the
report originated from its checker phase and bind it into a candidate result;
test execution/report persistence and commit remain later work.

## 8. Stable errors

Numeric codes 37000 through 37018 are closed in enum order:

- `POLICY_ROOT_DUPLICATE_INPUT`;
- `POLICY_ROOT_VERSION_UNSUPPORTED`;
- `POLICY_ROOT_EFFECT_KIND_UNKNOWN`;
- `POLICY_ROOT_MUTATION_CLASS_UNKNOWN`;
- `POLICY_ROOT_RESOURCE_LIMIT`;
- `POLICY_ROOT_TRANSITION_MODE_INVALID`;
- `POLICY_ROOT_FLAG_UNKNOWN`;
- `POLICY_GRANT_DENIED`;
- `POLICY_ISOLATION_POLICY_ROOT_MISMATCH`;
- `POLICY_ISOLATION_WORKSPACE_MISMATCH`;
- `POLICY_ISOLATION_POLICY_ROOT_CHANGED`;
- `POLICY_ISOLATION_SCHEMA_EPOCH_CHANGED`;
- `POLICY_ISOLATION_CONTRACT_ROOT_CHANGED`;
- `POLICY_ISOLATION_TEST_ROOT_CHANGED`;
- `POLICY_ISOLATION_PROTECTED_ENTITY_CHANGED`;
- `POLICY_FINAL_REPORT_INVALID`;
- `POLICY_FINAL_REQUIRED_TEST_MISSING`;
- `POLICY_FINAL_REQUIRED_CONTRACT_MISSING`;
- `POLICY_FINAL_REQUIRED_TEST_NOT_SELECTED`.

Exact earlier `SCB_*` and `SCHEMA_*` failures are preserved.

## 9. Acceptance and explicit gaps

Acceptance requires frozen descriptor hashes and vectors, 128 equal unordered
rebuilds, strict registry/import rejection, bounded collections/resources,
exact principal lookup denial, all protected-root/oracle/entity isolation
faults, and mandatory test/contract omission rejection.

S20-370 does not complete S20-350, S20-360, S20-380, S20-390, M3, M4, release,
or GA. Authenticated policy transitions, capability tokens, signatures/MACs,
nonce replay, live scope/budget/expiry enforcement, candidate integration,
receipts, ref CAS, and final production-epoch assembly remain blocked.
