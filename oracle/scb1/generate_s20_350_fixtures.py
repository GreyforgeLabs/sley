#!/usr/bin/env python3
"""Generate the independent supplemental S20-350 conformance corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
from copy import deepcopy
from pathlib import Path

from sley2_scb1_oracle.candidate import (
    CANDIDATE_DOMAIN,
    CANDIDATE_MAGIC,
    CONTRACT,
    SOURCE_SCHEMA_BLAKE3,
    _digest,
    _read_record,
    build_candidate,
    derive_entity_id,
    encode_candidate_record_unchecked,
    stored_from_record_bytes,
    validation_profile_id,
)
from sley2_scb1_oracle.codec import encode_record, encode_sized, encode_uvar
from sley2_scb1_oracle.mutation_value import _encode_type, encode_mutation_value


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "conformance/mutation-candidate/v1"


def hx(byte: int) -> str:
    return f"{byte:02x}" * 32


def type_expr(variant: str, value: object | None = None) -> dict[str, object]:
    result: dict[str, object] = {"variant": variant}
    if value is not None:
        result["value"] = value
    return result


def option(value: object | None = None) -> dict[str, object]:
    return {"variant": "None"} if value is None else {"variant": "Some", "value": value}


def const(value_type: dict[str, object], variant: str, value: object | None = None) -> dict[str, object]:
    data: dict[str, object] = {"variant": variant}
    if value is not None:
        data["value"] = value
    return {"value_type": value_type, "data": data}


BOOL_TRUE = const(type_expr("Bool"), "Bool", True)
BOOL_FALSE = const(type_expr("Bool"), "Bool", False)
UNIT = const(type_expr("Unit"), "Unit")
TEXT = const(type_expr("Text"), "Text", "sley")
LIMITS = {
    "fuel": 1_000,
    "memory_bytes": 1_048_576,
    "output_bytes": 65_536,
    "effect_count": 32,
    "call_depth": 16,
    "wall_timeout_millis": 5_000,
}
RETURN = {
    "variant": "Return",
    "value": {"value": {"variant": "Parameter", "value": hx(40)}},
}
BRANCH = {
    "variant": "Branch",
    "value": {"edge": {"target": hx(41), "arguments": []}},
}
COND_BRANCH = {
    "variant": "CondBranch",
    "value": {
        "condition": {"variant": "Parameter", "value": hx(42)},
        "if_true": {"target": hx(43), "arguments": []},
        "if_false": {"target": hx(44), "arguments": []},
    },
}
VARIANT_SWITCH = {
    "variant": "VariantSwitch",
    "value": {
        "value": {"variant": "Parameter", "value": hx(45)},
        "cases": [],
    },
}
TRAP = {
    "variant": "Trap",
    "value": {"code": "Unreachable", "payload": option()},
}
TYPE_FORM_RECORD = {
    "variant": "Record",
    "value": [
        {
            "member_id": hx(50),
            "value_type": type_expr("Bool"),
            "visibility": "Private",
        }
    ],
}
TYPE_FORM_VARIANT = {
    "variant": "Variant",
    "value": [{"member_id": hx(51), "payload_type": option(type_expr("Text"))}],
}
EFFECT_REPLAY = {
    "variant": "Replay",
    "value": [
        {
            "adapter_import": hx(52),
            "request": [BOOL_TRUE],
            "response": {"variant": "Ok", "value": BOOL_FALSE},
        }
    ],
}
EFFECT_CONFIG = {
    "variant": "DeterministicAdapters",
    "value": [{"adapter_import": hx(53), "configuration": TEXT}],
}
OUTCOME_VALUE = {"variant": "Value", "value": BOOL_TRUE}
OUTCOME_FAILURE = {"variant": "FailureCode", "value": 7}

NAMESPACE_BODY = {"parent": option(hx(54)), "members": [hx(55), hx(56)]}
TYPE_DEF_BODY = {
    "type_parameters": [{"ordinal": 0}],
    "form": TYPE_FORM_RECORD,
    "invariants": [hx(57)],
    "visibility": "Package",
}
BLOCK_BODY = {
    "function": hx(58),
    "parameters": [hx(59)],
    "operations": [hx(60)],
    "terminator": TRAP,
    "reachability": "Required",
}
CONSTANT_BODY = {"value": BOOL_TRUE}
CAPABILITY_BODY = {
    "effect": hx(61),
    "allowed_scopes": [TEXT],
    "constraint_contracts": [hx(62)],
}
CONTRACT_BODY = {
    "target": hx(63),
    "contract_kind": "Precondition",
    "predicate": hx(64),
    "bindings": [
        {
            "predicate_parameter": 0,
            "source": {"variant": "Parameter", "value": hx(65)},
        }
    ],
    "resource_limits": option(LIMITS),
}
TEST_BODY = {
    "target": hx(66),
    "inputs": [BOOL_TRUE],
    "effect_environment": EFFECT_REPLAY,
    "expected": OUTCOME_VALUE,
    "observations": [{"observation_id": hx(67), "value": BOOL_FALSE}],
    "resource_limits": LIMITS,
}


def constant_vectors() -> list[tuple[str, str, object]]:
    named = type_expr("Named", {"definition": hx(70), "arguments": []})
    uint8 = type_expr("UInt", 8)
    values = [
        ("const_unit", "ConstValue", UNIT),
        ("const_bool", "ConstValue", BOOL_TRUE),
        ("const_sint", "ConstValue", const(type_expr("SInt", 8), "SInt", -1)),
        ("const_uint", "ConstValue", const(uint8, "UInt", 255)),
        ("const_f32", "ConstValue", const(type_expr("F32"), "F32Bits", "3f800000")),
        (
            "const_f64",
            "ConstValue",
            const(type_expr("F64"), "F64Bits", "3ff0000000000000"),
        ),
        ("const_bytes", "ConstValue", const(type_expr("Bytes"), "Bytes", "0001ff")),
        ("const_text", "ConstValue", TEXT),
        (
            "const_sequence",
            "ConstValue",
            const(type_expr("Tuple", [type_expr("Bool")]), "Sequence", [BOOL_TRUE]),
        ),
        (
            "const_record",
            "ConstValue",
            const(
                named,
                "Record",
                {
                    "definition": hx(70),
                    "fields": [{"member_id": hx(71), "value": BOOL_TRUE}],
                },
            ),
        ),
        (
            "const_variant",
            "ConstValue",
            const(
                named,
                "Variant",
                {"definition": hx(70), "member_id": hx(72), "payload": option(TEXT)},
            ),
        ),
        (
            "const_map",
            "ConstValue",
            const(
                type_expr("OrderedMap", {"key": uint8, "value": type_expr("Bool")}),
                "Map",
                [
                    {"key": const(uint8, "UInt", 1), "value": BOOL_FALSE},
                    {"key": const(uint8, "UInt", 2), "value": BOOL_TRUE},
                ],
            ),
        ),
        (
            "const_option",
            "ConstValue",
            const(type_expr("Option", type_expr("Bool")), "Option", option(BOOL_TRUE)),
        ),
        (
            "const_result",
            "ConstValue",
            const(
                type_expr(
                    "Result", {"ok": type_expr("Bool"), "error": type_expr("Text")}
                ),
                "Result",
                {"variant": "Ok", "value": BOOL_TRUE},
            ),
        ),
        (
            "const_function_ref",
            "ConstValue",
            const(
                type_expr(
                    "FunctionRef",
                    {"parameters": [], "result": type_expr("Unit"), "effects": []},
                ),
                "FunctionRef",
                {"function": hx(73), "type_arguments": []},
            ),
        ),
        (
            "const_builtin_failure",
            "ConstValue",
            const(
                type_expr("BuiltinFailure", "ArithmeticError"),
                "BuiltinFailure",
                {"kind": "ArithmeticError", "code": 1},
            ),
        ),
    ]
    return values


def value_vector_sources() -> list[tuple[str, str, object]]:
    values = constant_vectors()
    values.extend(
        [
            ("terminator_return", "Terminator", RETURN),
            ("terminator_branch", "Terminator", BRANCH),
            ("terminator_cond_branch", "Terminator", COND_BRANCH),
            ("terminator_variant_switch", "Terminator", VARIANT_SWITCH),
            ("terminator_trap", "Terminator", TRAP),
            ("type_def_form_record", "TypeDefForm", TYPE_FORM_RECORD),
            ("type_def_form_variant", "TypeDefForm", TYPE_FORM_VARIANT),
            ("effect_environment_replay", "EffectEnvironment", EFFECT_REPLAY),
            ("effect_environment_config", "EffectEnvironment", EFFECT_CONFIG),
            ("expected_outcome_value", "ExpectedOutcome", OUTCOME_VALUE),
            ("expected_outcome_failure", "ExpectedOutcome", OUTCOME_FAILURE),
            ("body_namespace", "NamespaceBody", NAMESPACE_BODY),
            ("body_type_def", "TypeDefBody", TYPE_DEF_BODY),
            ("body_block", "BlockBody", BLOCK_BODY),
            ("body_constant", "ConstantBody", CONSTANT_BODY),
            (
                "body_capability_requirement",
                "CapabilityRequirementBody",
                CAPABILITY_BODY,
            ),
            ("body_contract", "ContractBody", CONTRACT_BODY),
            ("body_test_case", "TestCaseBody", TEST_BODY),
            ("field_namespace_parent", "Option<EntityId>", NAMESPACE_BODY["parent"]),
            ("field_type_def_form", "TypeDefForm", TYPE_DEF_BODY["form"]),
            ("field_block_terminator", "Terminator", BLOCK_BODY["terminator"]),
            ("field_constant_value", "ConstValue", CONSTANT_BODY["value"]),
            (
                "field_capability_requirement_allowed_scopes",
                "List<ConstValue>",
                CAPABILITY_BODY["allowed_scopes"],
            ),
            (
                "field_contract_resource_limits",
                "Option<ResourceLimits>",
                CONTRACT_BODY["resource_limits"],
            ),
            ("field_test_case_inputs", "List<ConstValue>", TEST_BODY["inputs"]),
            (
                "field_test_case_effect_environment",
                "EffectEnvironment",
                TEST_BODY["effect_environment"],
            ),
            (
                "field_test_case_expected",
                "ExpectedOutcome",
                TEST_BODY["expected"],
            ),
            (
                "field_test_case_observations",
                "List<ExpectedObservation>",
                TEST_BODY["observations"],
            ),
        ]
    )
    return values


def candidate_record() -> dict[str, object]:
    workspace = bytes.fromhex(hx(1))
    nonce = bytes.fromhex(hx(12))
    create_target = derive_entity_id(workspace, nonce, 1, 0).hex()
    targets = [create_target] + [hx(80 + index) for index in range(1, 16)]
    workspace_body = {
        "packages": [],
        "root_namespace": hx(100),
        "capability_requirements": [],
        "contracts": [],
        "tests": [],
    }
    package_body = {
        "workspace": hx(1),
        "root_namespace": hx(101),
        "dependencies": [],
        "exports": [],
    }
    operations = [
        ("CreateEntity", 1, None, workspace_body),
        ("ReplaceEntityVersion", 2, None, package_body),
        ("DeleteEntityBinding", 3, None, None),
        ("SetScalarField", 6, 3, 7),
        ("ReplaceTypedField", 9, 1, BOOL_TRUE),
        ("RetargetReference", 3, 1, option(hx(102))),
        ("InsertOrderedChild", 5, 6, {"index": 0, "child": hx(103)}),
        (
            "RemoveOrderedChild",
            5,
            6,
            {"index": 1, "expected_child": hx(104)},
        ),
        (
            "MoveOrderedChild",
            5,
            6,
            {"from": 0, "to": 1, "expected_child": hx(105)},
        ),
        ("AddEntryPoint", 16, None, {"function": hx(106), "exposure": "Local"}),
        ("RemoveEntryPoint", 16, None, None),
        ("AddTest", 14, None, TEST_BODY),
        ("ReplaceTest", 14, None, TEST_BODY),
        ("AddContract", 13, None, CONTRACT_BODY),
        ("ReplaceContract", 13, None, CONTRACT_BODY),
        (
            "UpdateDependencyBinding",
            18,
            None,
            {
                "dependency_root": hx(107),
                "external_package": hx(108),
                "local_namespace": hx(109),
            },
        ),
    ]
    encoded_operations: list[dict[str, object]] = []
    preconditions: list[dict[str, object]] = []
    for ordinal, ((class_name, kind, field_tag, payload), target) in enumerate(
        zip(operations, targets)
    ):
        encoded_operations.append(
            {
                "ordinal": ordinal,
                "class": class_name,
                "target_kind": kind,
                "target_entity": target,
                "field_tag": field_tag,
                "payload": payload,
                "precondition_ordinal": ordinal,
            }
        )
        if class_name == "CreateEntity":
            requirement = "ExpectedIdentityAbsent"
            preimage = {"entity_id": target}
        elif class_name in {
            "InsertOrderedChild",
            "RemoveOrderedChild",
            "MoveOrderedChild",
        }:
            requirement = "ExactContainerVersion"
            preimage = {
                "container_id": target,
                "object_id": hx(120 + ordinal),
                "field_tag": field_tag,
            }
        else:
            requirement = "ExactEntityVersion"
            preimage = {"entity_id": target, "object_id": hx(120 + ordinal)}
        preconditions.append(
            {
                "operation_ordinal": ordinal,
                "requirement": requirement,
                "payload": preimage,
            }
        )
    return {
        "format_version": 1,
        "workspace_id": hx(1),
        "base_transaction_id": hx(2),
        "base_root": hx(3),
        "schema_epoch_id": hx(4),
        "policy_root_id": hx(5),
        "principal_id": hx(6),
        "capability_summary_digest": hx(7),
        "operations": encoded_operations,
        "preconditions": preconditions,
        "validation_profile_id": validation_profile_id().hex(),
        "candidate_nonce": hx(12),
        "expiry": {"clock": 1, "not_after": 2_000_000_000_000},
    }


def accepted_corpus() -> dict[str, object]:
    value_vectors = []
    for vector_id, declared_type, value in value_vector_sources():
        value_vectors.append(
            {
                "id": vector_id,
                "declared_type": declared_type,
                "value": value,
                "expected_hex": encode_mutation_value(declared_type, value).hex(),
            }
        )
    record = candidate_record()
    built = build_candidate(record)
    candidate_vectors = [
        {
            "id": "candidate_all_16_classes",
            "record": record,
            "expected_record_hex": built["record"].hex(),
            "expected_preimage_hex": built["preimage"].hex(),
            "expected_candidate_id": built["candidate_id"].hex(),
            "expected_stored_hex": built["stored"].hex(),
        }
    ]
    return {
        "claim": "complete-s20-350-conformance",
        "contract": CONTRACT,
        "source_schema_blake3": SOURCE_SCHEMA_BLAKE3,
        "coverage": {
            "supplemental_entity_bodies": 7,
            "supplemental_manifest_fields": 10,
            "const_data_variants": 16,
            "terminator_variants": 5,
            "mutation_classes": 16,
            "combined_with": "conformance/mutation-value/v1/accepted.json",
            "combined_entity_bodies": 18,
            "combined_manifest_fields": 75,
        },
        "value_vectors": value_vectors,
        "candidate_vectors": candidate_vectors,
    }


def raw_record(fields: dict[int, bytes], tags: list[int]) -> bytes:
    return encode_record([(tag, fields[tag]) for tag in tags])


def rejected_corpus(accepted: dict[str, object]) -> dict[str, object]:
    candidate_vector = accepted["candidate_vectors"][0]  # type: ignore[index]
    record = deepcopy(candidate_vector["record"])  # type: ignore[index]
    built = build_candidate(record)

    value_rejections = [
        ("reject_option_unknown", "Option<EntityId>", "0200", "SCB_UNION_INVALID"),
        ("reject_option_none_payload", "Option<EntityId>", "000100", "SCB_UNION_INVALID"),
        ("reject_terminator_unknown", "Terminator", "0600", "SCB_UNION_INVALID"),
        ("reject_const_data_unit_payload", "ConstData", "010100", "SCB_UNION_INVALID"),
    ]

    candidate_rejections: list[tuple[str, bytes, str]] = []
    wrong_magic = bytearray(built["stored"])
    wrong_magic[0] ^= 0x01
    candidate_rejections.append(("reject_candidate_magic", bytes(wrong_magic), "SCB_MAGIC_INVALID"))

    version_preimage = CANDIDATE_MAGIC + encode_uvar(2) + encode_sized(built["record"])
    candidate_rejections.append(
        (
            "reject_candidate_version",
            version_preimage + _digest(CANDIDATE_DOMAIN, version_preimage),
            "SCB_VERSION_UNSUPPORTED",
        )
    )
    wrong_digest = bytearray(built["stored"])
    wrong_digest[-1] ^= 0x01
    candidate_rejections.append(
        ("reject_candidate_digest", bytes(wrong_digest), "SCB_DIGEST_MISMATCH")
    )
    trailing_preimage = built["preimage"] + b"\x00"
    candidate_rejections.append(
        (
            "reject_candidate_preimage_trailing",
            trailing_preimage + _digest(CANDIDATE_DOMAIN, trailing_preimage),
            "SCB_TRAILING_BYTES",
        )
    )

    fields = _read_record(built["record"], list(range(1, 14)))
    missing_record = raw_record(fields, list(range(1, 13)))
    candidate_rejections.append(
        ("reject_candidate_record_missing", stored_from_record_bytes(missing_record), "SCB_FIELD_MISSING")
    )
    unknown_record = encode_record(
        [(tag, fields[tag]) for tag in range(1, 14)] + [(14, b"")]
    )
    candidate_rejections.append(
        ("reject_candidate_record_unknown", stored_from_record_bytes(unknown_record), "SCB_FIELD_UNKNOWN")
    )

    alternatives: list[tuple[str, dict[str, object], str]] = []
    empty = deepcopy(record)
    empty["operations"] = []
    empty["preconditions"] = []
    alternatives.append(("reject_candidate_empty", empty, "MUTATION_CANDIDATE_EMPTY_OPERATIONS"))
    wrong_ordinal = deepcopy(record)
    wrong_ordinal["operations"][1]["ordinal"] = 3
    alternatives.append(
        ("reject_candidate_ordinal", wrong_ordinal, "MUTATION_CANDIDATE_OPERATION_ORDINAL")
    )
    wrong_binding = deepcopy(record)
    wrong_binding["operations"][1]["precondition_ordinal"] = 9
    alternatives.append(
        (
            "reject_candidate_operation_precondition_ordinal",
            wrong_binding,
            "MUTATION_CANDIDATE_OPERATION_PRECONDITION_ORDINAL",
        )
    )
    wrong_target = deepcopy(record)
    wrong_target["operations"][0]["target_entity"] = hx(254)
    wrong_target["preconditions"][0]["payload"]["entity_id"] = hx(254)
    alternatives.append(
        ("reject_candidate_create_target", wrong_target, "MUTATION_CANDIDATE_TARGET_ENTITY")
    )
    wrong_precondition = deepcopy(record)
    wrong_precondition["preconditions"][2]["payload"]["entity_id"] = hx(253)
    alternatives.append(
        (
            "reject_candidate_precondition_target",
            wrong_precondition,
            "MUTATION_CANDIDATE_PRECONDITION_MISMATCH",
        )
    )
    wrong_profile = deepcopy(record)
    wrong_profile["validation_profile_id"] = hx(252)
    alternatives.append(
        (
            "reject_candidate_profile",
            wrong_profile,
            "MUTATION_CANDIDATE_VALIDATION_PROFILE",
        )
    )
    wrong_expiry = deepcopy(record)
    wrong_expiry["expiry"]["not_after"] = 0
    alternatives.append(
        ("reject_candidate_expiry", wrong_expiry, "MUTATION_CANDIDATE_EXPIRY_INVALID")
    )
    missing_precondition = deepcopy(record)
    missing_precondition["preconditions"].pop()
    alternatives.append(
        (
            "reject_candidate_precondition_count",
            missing_precondition,
            "MUTATION_CANDIDATE_PRECONDITION_COUNT",
        )
    )
    for vector_id, alternate, code in alternatives:
        raw = encode_candidate_record_unchecked(alternate)
        candidate_rejections.append((vector_id, stored_from_record_bytes(raw), code))

    return {
        "claim": "complete-s20-350-conformance",
        "contract": CONTRACT,
        "source_schema_blake3": SOURCE_SCHEMA_BLAKE3,
        "value_vectors": [
            {
                "id": vector_id,
                "declared_type": declared_type,
                "input_hex": raw,
                "expected_code": code,
            }
            for vector_id, declared_type, raw, code in value_rejections
        ],
        "candidate_vectors": [
            {"id": vector_id, "input_hex": raw.hex(), "expected_code": code}
            for vector_id, raw, code in candidate_rejections
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if committed output differs")
    args = parser.parse_args()
    accepted = accepted_corpus()
    rejected = rejected_corpus(accepted)
    documents = {
        "accepted.json": json.dumps(accepted, indent=2, sort_keys=True) + "\n",
        "rejected.json": json.dumps(rejected, indent=2, sort_keys=True) + "\n",
    }
    sums = "".join(
        f"{hashlib.sha256(documents[name].encode()).hexdigest()}  {name}\n"
        for name in ("accepted.json", "rejected.json")
    )
    documents["SHA256SUMS"] = sums
    if args.check:
        stale = [
            name
            for name, expected in documents.items()
            if not (OUTPUT / name).is_file()
            or (OUTPUT / name).read_text(encoding="utf-8") != expected
        ]
        if stale:
            raise SystemExit(f"stale S20-350 fixtures: {', '.join(stale)}")
        return
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, document in documents.items():
        (OUTPUT / name).write_text(document, encoding="utf-8")


if __name__ == "__main__":
    main()
