#!/usr/bin/env python3
"""Fail-closed frozen-artifact adapter and retained version smoke for S20-600.

This module has one executable command surface: the exact ``bin/sley
--version`` smoke from a privately copied, fully verified, mode-hardened staging
tree. It does not contain a model/provider adapter, benchmark task runner,
oracle adapter, network-isolation claim, or interaction with a live Sley 1.x
checkout.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ARTIFACT_PATH = Path(
    os.environ.get(
        "SLEY1_ARTIFACT_PATH",
        Path.home() / "archive" / "sley" / "1.2.0" / "sley-1.2.0-linux-x86_64.tar.gz",
    )
)
VERSION_ARGUMENTS = ("--version",)
SMOKE_CONTRACT = "sley2.legacy-version-smoke.v1"
VERIFICATION_CONTRACT = "sley2.legacy-artifact-verification.v1"
EVIDENCE_SCOPE = "VERIFIED_FROZEN_ARTIFACT_VERSION_SMOKE_ONLY"
MANIFEST_RELATIVE_PATH = "release/manifest.json"
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class LegacyErrorCode(IntEnum):
    """Stable S20-600 artifact-adapter failure codes."""

    ARTIFACT_MISSING = 60_000
    ARTIFACT_IDENTITY_MISMATCH = 60_001
    ARCHIVE_INVALID = 60_002
    ARCHIVE_MEMBER_UNSAFE = 60_003
    ARCHIVE_LIMIT_EXCEEDED = 60_004
    MANIFEST_INVALID = 60_005
    MANIFEST_IDENTITY_MISMATCH = 60_006
    PAYLOAD_MISMATCH = 60_007
    STAGING_FAILED = 60_008
    COMMAND_NOT_ALLOWED = 60_009
    COMMAND_TIMEOUT = 60_010
    COMMAND_OUTPUT_LIMIT = 60_011
    COMMAND_FAILED = 60_012
    EVIDENCE_WRITE_FAILED = 60_013
    INTERNAL_INVARIANT = 60_014

    @property
    def symbol(self) -> str:
        return f"LEGACY_{self.name}"


class LegacyRunnerError(ValueError):
    """One stable fail-closed legacy-adapter error."""

    def __init__(self, code: LegacyErrorCode, detail: str = "") -> None:
        super().__init__(code.symbol if not detail else f"{code.symbol}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: LegacyErrorCode, detail: str = "") -> None:
    raise LegacyRunnerError(code, detail)


@dataclass(frozen=True)
class LegacyArtifactContract:
    """Pinned identity and bounded extraction contract for one legacy artifact."""

    artifact_sha256: str
    artifact_size_bytes: int
    top_level_directory: str
    release: str
    source_commit: str
    artifact_id: str
    expected_version_output: str
    payload_tree_digest: str | None = None
    expected_archive_member_count: int | None = None
    expected_regular_file_count: int | None = None
    expected_payload_file_count: int | None = None
    expected_payload_total_bytes: int | None = None
    expected_sley_digest: str | None = None
    manifest_schema: str = "sley.release.manifest.v1"
    max_archive_members: int = 2_048
    max_regular_files: int = 1_200
    max_total_regular_bytes: int = 16 * 1024 * 1024
    max_member_bytes: int = 8 * 1024 * 1024
    max_manifest_bytes: int = 2 * 1024 * 1024
    metadata_paths: tuple[str, ...] = (
        "release/licenses.json",
        "release/manifest.json",
        "release/sbom.spdx.json",
    )


FROZEN_CONTRACT = LegacyArtifactContract(
    artifact_sha256="b24f19c6a348751c93c9cf63f6f4154f6132796112c26f9d8c0e71324080dbc7",
    artifact_size_bytes=4_611_024,
    top_level_directory="sley-1.2.0-linux-x86_64",
    release="1.2.0",
    source_commit="397fa28ded15ddbeca5404ee00a3f5bd5546b296",
    artifact_id="sley-1.2.0-linux-x86_64",
    expected_version_output="sley 1.2.0",
    payload_tree_digest="sha256:548e0057c0b1543b0c926051beb085653942ccddba93e6b60864382321a4d8de",
    expected_archive_member_count=1_568,
    expected_regular_file_count=1_070,
    expected_payload_file_count=1_067,
    expected_payload_total_bytes=8_610_725,
    expected_sley_digest="c9d56feeb575653aff7c9cabf629902a307b18af1542248292cf0ce278843d6c",
)


@dataclass(frozen=True)
class ArchivedFile:
    """Verified metadata for one regular archive member."""

    relative_path: str
    size: int
    mode: int
    sha256: str


@dataclass(frozen=True)
class VerifiedLegacyArtifact:
    """Complete verified identity needed for safe private staging."""

    source_path: Path
    artifact_sha256: str
    artifact_size_bytes: int
    archive_member_count: int
    directory_count: int
    regular_file_count: int
    total_regular_bytes: int
    manifest_sha256: str
    payload_tree_digest: str
    payload_file_count: int
    payload_total_bytes: int
    archived_files: tuple[ArchivedFile, ...]
    archived_directories: tuple[str, ...]

    def report(self) -> dict[str, Any]:
        return {
            "contract": VERIFICATION_CONTRACT,
            "source_path": str(self.source_path),
            "artifact_sha256": self.artifact_sha256,
            "artifact_size_bytes": self.artifact_size_bytes,
            "archive_member_count": self.archive_member_count,
            "directory_count": self.directory_count,
            "regular_file_count": self.regular_file_count,
            "total_regular_bytes": self.total_regular_bytes,
            "manifest_sha256": self.manifest_sha256,
            "payload_tree_digest": self.payload_tree_digest,
            "payload_file_count": self.payload_file_count,
            "payload_total_bytes": self.payload_total_bytes,
            "outer_identity_verified": True,
            "archive_safety_verified": True,
            "manifest_identity_verified": True,
            "payload_inventory_verified": True,
        }


@dataclass(frozen=True)
class LegacyStage:
    """Private, temporary, write-bit-stripped stage for the verified artifact."""

    root: Path
    scratch: Path
    verified: VerifiedLegacyArtifact


def _utc_second() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic JSON bytes for local evidence digests."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _stream_sha256(file_object: Any, *, limit: int | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = file_object.read(128 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if limit is not None and total > limit:
            _fail(LegacyErrorCode.ARCHIVE_LIMIT_EXCEEDED, "regular member bytes")
        digest.update(chunk)
    return digest.hexdigest(), total


def _open_regular_nofollow(path: Path) -> Any:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | O_NOFOLLOW)
    except FileNotFoundError as error:
        raise LegacyRunnerError(LegacyErrorCode.ARTIFACT_MISSING, str(path)) from error
    except OSError as error:
        raise LegacyRunnerError(
            LegacyErrorCode.ARTIFACT_IDENTITY_MISMATCH, str(error)
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            _fail(LegacyErrorCode.ARTIFACT_IDENTITY_MISMATCH, "artifact is not regular")
        return os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise


def _validate_contract(contract: LegacyArtifactContract) -> None:
    if HEX_64.fullmatch(contract.artifact_sha256) is None:
        _fail(LegacyErrorCode.INTERNAL_INVARIANT, "invalid contract artifact digest")
    if contract.artifact_size_bytes <= 0:
        _fail(LegacyErrorCode.INTERNAL_INVARIANT, "invalid contract artifact size")
    if (
        not contract.top_level_directory
        or "/" in contract.top_level_directory
        or "\\" in contract.top_level_directory
        or contract.top_level_directory in {".", ".."}
    ):
        _fail(LegacyErrorCode.INTERNAL_INVARIANT, "invalid contract top directory")
    if len(set(contract.metadata_paths)) != len(contract.metadata_paths):
        _fail(LegacyErrorCode.INTERNAL_INVARIANT, "duplicate contract metadata path")


def _member_relative_path(
    member: tarfile.TarInfo, contract: LegacyArtifactContract
) -> str:
    name = member.name
    if not name or "\x00" in name or "\\" in name or len(name.encode("utf-8")) > 4_096:
        _fail(LegacyErrorCode.ARCHIVE_MEMBER_UNSAFE, "invalid member name")
    normalized = name[:-1] if member.isdir() and name.endswith("/") else name
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        _fail(LegacyErrorCode.ARCHIVE_MEMBER_UNSAFE, name)
    if str(pure) != normalized or pure.parts[0] != contract.top_level_directory:
        _fail(LegacyErrorCode.ARCHIVE_MEMBER_UNSAFE, name)
    if member.isfile() and name.endswith("/"):
        _fail(LegacyErrorCode.ARCHIVE_MEMBER_UNSAFE, name)
    if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
        _fail(LegacyErrorCode.ARCHIVE_MEMBER_UNSAFE, f"unsupported member type: {name}")
    if member.mode < 0 or member.mode & ~0o777:
        _fail(LegacyErrorCode.ARCHIVE_MEMBER_UNSAFE, f"unsafe mode: {name}")
    return PurePosixPath(*pure.parts[1:]).as_posix() if len(pure.parts) > 1 else ""


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_manifest(payload: bytes, contract: LegacyArtifactContract) -> dict[str, Any]:
    if len(payload) > contract.max_manifest_bytes:
        _fail(LegacyErrorCode.ARCHIVE_LIMIT_EXCEEDED, "manifest bytes")
    try:
        value = json.loads(payload, object_pairs_hook=_strict_json_object)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise LegacyRunnerError(LegacyErrorCode.MANIFEST_INVALID, str(error)) from error
    if not isinstance(value, dict):
        _fail(LegacyErrorCode.MANIFEST_INVALID, "manifest is not an object")
    return value


def _require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _fail(LegacyErrorCode.MANIFEST_INVALID, field)
    return value


def _safe_payload_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        _fail(LegacyErrorCode.MANIFEST_INVALID, field)
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or str(pure) != value
    ):
        _fail(LegacyErrorCode.MANIFEST_INVALID, field)
    return value


def _manifest_inventory(
    manifest: Mapping[str, Any], contract: LegacyArtifactContract
) -> tuple[dict[str, ArchivedFile], str, int, int]:
    expected_identity = {
        "schema": contract.manifest_schema,
        "artifact_id": contract.artifact_id,
        "release": contract.release,
        "status": "release_candidate",
    }
    for field, expected in expected_identity.items():
        if manifest.get(field) != expected:
            _fail(LegacyErrorCode.MANIFEST_IDENTITY_MISMATCH, field)

    source = _require_mapping(manifest.get("source"), "source")
    if (
        source.get("commit") != contract.source_commit
        or source.get("dirty") is not False
    ):
        _fail(LegacyErrorCode.MANIFEST_IDENTITY_MISMATCH, "source")
    payload_tree_digest = source.get("payload_tree_digest")
    if (
        not isinstance(payload_tree_digest, str)
        or not payload_tree_digest.startswith("sha256:")
        or HEX_64.fullmatch(payload_tree_digest[7:]) is None
    ):
        _fail(LegacyErrorCode.MANIFEST_INVALID, "source.payload_tree_digest")
    if (
        contract.payload_tree_digest is not None
        and payload_tree_digest != contract.payload_tree_digest
    ):
        _fail(LegacyErrorCode.MANIFEST_IDENTITY_MISMATCH, "source.payload_tree_digest")

    authority = _require_mapping(manifest.get("authority"), "authority")
    expected_authority = {
        "mode": "local_release_candidate_only",
        "publication_authorized": False,
        "signing_status": "unsigned",
        "tag_authorized": False,
        "upload_authorized": False,
    }
    if dict(authority) != expected_authority:
        _fail(LegacyErrorCode.MANIFEST_IDENTITY_MISMATCH, "authority")

    platform = _require_mapping(manifest.get("platform"), "platform")
    expected_platform = {
        "architecture": "x86_64",
        "archive_format": "tar.gz",
        "os": "linux",
        "support_status": "supported",
    }
    if dict(platform) != expected_platform:
        _fail(LegacyErrorCode.MANIFEST_IDENTITY_MISMATCH, "platform")

    metadata = _require_mapping(manifest.get("metadata"), "metadata")
    expected_metadata = {
        "license_inventory": "release/licenses.json",
        "manifest": "release/manifest.json",
        "sbom": "release/sbom.spdx.json",
    }
    if dict(metadata) != expected_metadata or set(metadata.values()) != set(
        contract.metadata_paths
    ):
        _fail(LegacyErrorCode.MANIFEST_IDENTITY_MISMATCH, "metadata")

    toolchain = _require_mapping(manifest.get("toolchain"), "toolchain")
    if toolchain.get("sley_version") != contract.expected_version_output:
        _fail(LegacyErrorCode.MANIFEST_IDENTITY_MISMATCH, "toolchain.sley_version")

    payload = _require_mapping(manifest.get("payload"), "payload")
    if (
        payload.get("inventory_scope")
        != "tracked_release_payload_excluding_release_metadata"
    ):
        _fail(LegacyErrorCode.MANIFEST_IDENTITY_MISMATCH, "payload.inventory_scope")
    file_count = payload.get("file_count")
    total_bytes = payload.get("total_bytes")
    files = payload.get("files")
    if (
        isinstance(file_count, bool)
        or not isinstance(file_count, int)
        or file_count < 1
        or isinstance(total_bytes, bool)
        or not isinstance(total_bytes, int)
        or total_bytes < 1
        or not isinstance(files, list)
        or len(files) != file_count
    ):
        _fail(LegacyErrorCode.MANIFEST_INVALID, "payload counts")
    if (
        contract.expected_payload_file_count is not None
        and file_count != contract.expected_payload_file_count
    ):
        _fail(LegacyErrorCode.MANIFEST_IDENTITY_MISMATCH, "payload.file_count")
    if (
        contract.expected_payload_total_bytes is not None
        and total_bytes != contract.expected_payload_total_bytes
    ):
        _fail(LegacyErrorCode.MANIFEST_IDENTITY_MISMATCH, "payload.total_bytes")

    inventory: dict[str, ArchivedFile] = {}
    previous_path = ""
    computed_total = 0
    metadata_paths = set(contract.metadata_paths)
    for index, record_value in enumerate(files):
        record = _require_mapping(record_value, f"payload.files[{index}]")
        if set(record) != {"digest", "mode", "path", "size"}:
            _fail(LegacyErrorCode.MANIFEST_INVALID, f"payload.files[{index}] fields")
        path = _safe_payload_path(
            record.get("path"), field=f"payload.files[{index}].path"
        )
        if (
            path <= previous_path
            or path in metadata_paths
            or path.startswith("release/")
        ):
            _fail(
                LegacyErrorCode.MANIFEST_INVALID,
                f"payload.files[{index}].path order/scope",
            )
        previous_path = path
        digest = record.get("digest")
        mode_text = record.get("mode")
        size = record.get("size")
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or HEX_64.fullmatch(digest[7:]) is None
            or not isinstance(mode_text, str)
            or re.fullmatch(r"0[0-7]{3}", mode_text) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > contract.max_member_bytes
        ):
            _fail(LegacyErrorCode.MANIFEST_INVALID, f"payload.files[{index}]")
        inventory[path] = ArchivedFile(path, size, int(mode_text, 8), digest[7:])
        computed_total += size
    if computed_total != total_bytes:
        _fail(LegacyErrorCode.PAYLOAD_MISMATCH, "payload.total_bytes")
    return inventory, payload_tree_digest, file_count, total_bytes


def verify_frozen_artifact(
    artifact_path: Path = DEFAULT_ARTIFACT_PATH,
    contract: LegacyArtifactContract = FROZEN_CONTRACT,
) -> VerifiedLegacyArtifact:
    """Verify outer identity, archive safety, manifest identity, and every payload byte."""

    _validate_contract(contract)
    path = Path(artifact_path)
    try:
        with _open_regular_nofollow(path) as artifact:
            metadata = os.fstat(artifact.fileno())
            if metadata.st_size != contract.artifact_size_bytes:
                _fail(LegacyErrorCode.ARTIFACT_IDENTITY_MISMATCH, "size")
            outer_digest, outer_size = _stream_sha256(artifact)
            if (
                outer_size != contract.artifact_size_bytes
                or outer_digest != contract.artifact_sha256
            ):
                _fail(LegacyErrorCode.ARTIFACT_IDENTITY_MISMATCH, "sha256")
            artifact.seek(0)
            return _verify_open_archive(
                path, artifact, contract, outer_digest, outer_size
            )
    except LegacyRunnerError:
        raise
    except (OSError, EOFError, tarfile.TarError) as error:
        raise LegacyRunnerError(LegacyErrorCode.ARCHIVE_INVALID, str(error)) from error


def _verify_open_archive(
    source_path: Path,
    artifact: Any,
    contract: LegacyArtifactContract,
    outer_digest: str,
    outer_size: int,
) -> VerifiedLegacyArtifact:
    files: dict[str, ArchivedFile] = {}
    directories: set[str] = set()
    names: set[str] = set()
    manifest_bytes: bytes | None = None
    member_count = 0
    total_regular_bytes = 0
    try:
        archive = tarfile.open(fileobj=artifact, mode="r:gz")
        with archive:
            for member in archive:
                member_count += 1
                if member_count > contract.max_archive_members:
                    _fail(LegacyErrorCode.ARCHIVE_LIMIT_EXCEEDED, "archive members")
                relative = _member_relative_path(member, contract)
                if relative in names:
                    _fail(
                        LegacyErrorCode.ARCHIVE_MEMBER_UNSAFE,
                        f"duplicate: {member.name}",
                    )
                names.add(relative)
                if member.isdir():
                    directories.add(relative)
                    continue
                if member.size < 0 or member.size > contract.max_member_bytes:
                    _fail(LegacyErrorCode.ARCHIVE_LIMIT_EXCEEDED, member.name)
                if len(files) >= contract.max_regular_files:
                    _fail(LegacyErrorCode.ARCHIVE_LIMIT_EXCEEDED, "regular files")
                extracted = archive.extractfile(member)
                if extracted is None:
                    _fail(LegacyErrorCode.ARCHIVE_INVALID, member.name)
                capture_manifest = relative == MANIFEST_RELATIVE_PATH
                if capture_manifest:
                    payload = extracted.read(contract.max_manifest_bytes + 1)
                    if len(payload) > contract.max_manifest_bytes or extracted.read(1):
                        _fail(LegacyErrorCode.ARCHIVE_LIMIT_EXCEEDED, "manifest bytes")
                    digest = hashlib.sha256(payload).hexdigest()
                    size = len(payload)
                    manifest_bytes = payload
                else:
                    digest, size = _stream_sha256(
                        extracted, limit=contract.max_member_bytes
                    )
                if size != member.size:
                    _fail(LegacyErrorCode.ARCHIVE_INVALID, f"truncated: {member.name}")
                total_regular_bytes += size
                if total_regular_bytes > contract.max_total_regular_bytes:
                    _fail(LegacyErrorCode.ARCHIVE_LIMIT_EXCEEDED, "total regular bytes")
                files[relative] = ArchivedFile(relative, size, member.mode, digest)
    except LegacyRunnerError:
        raise
    except (OSError, EOFError, tarfile.TarError) as error:
        raise LegacyRunnerError(LegacyErrorCode.ARCHIVE_INVALID, str(error)) from error

    if manifest_bytes is None or MANIFEST_RELATIVE_PATH not in files:
        _fail(LegacyErrorCode.MANIFEST_INVALID, "release/manifest.json missing")
    if "" not in directories:
        _fail(LegacyErrorCode.ARCHIVE_MEMBER_UNSAFE, "top directory missing")
    required_directories = {""}
    for relative in files:
        parent = PurePosixPath(relative).parent
        while str(parent) != ".":
            required_directories.add(parent.as_posix())
            parent = parent.parent
    if directories != required_directories:
        _fail(LegacyErrorCode.ARCHIVE_MEMBER_UNSAFE, "directory inventory drift")

    manifest = _load_manifest(manifest_bytes, contract)
    payload_inventory, tree_digest, payload_count, payload_bytes = _manifest_inventory(
        manifest, contract
    )
    archive_payload_paths = set(files) - set(contract.metadata_paths)
    if archive_payload_paths != set(payload_inventory):
        _fail(LegacyErrorCode.PAYLOAD_MISMATCH, "payload path inventory")
    if not set(contract.metadata_paths).issubset(files):
        _fail(LegacyErrorCode.PAYLOAD_MISMATCH, "release metadata inventory")
    for relative, expected in payload_inventory.items():
        actual = files[relative]
        if actual != expected:
            _fail(LegacyErrorCode.PAYLOAD_MISMATCH, relative)

    sley = files.get("bin/sley")
    if sley is None or sley.mode & 0o111 == 0:
        _fail(LegacyErrorCode.PAYLOAD_MISMATCH, "bin/sley executable")
    if (
        contract.expected_sley_digest is not None
        and sley.sha256 != contract.expected_sley_digest
    ):
        _fail(LegacyErrorCode.PAYLOAD_MISMATCH, "bin/sley digest")
    if (
        contract.expected_archive_member_count is not None
        and member_count != contract.expected_archive_member_count
    ):
        _fail(LegacyErrorCode.ARCHIVE_INVALID, "archive member count")
    if (
        contract.expected_regular_file_count is not None
        and len(files) != contract.expected_regular_file_count
    ):
        _fail(LegacyErrorCode.ARCHIVE_INVALID, "regular file count")

    return VerifiedLegacyArtifact(
        source_path=source_path,
        artifact_sha256=outer_digest,
        artifact_size_bytes=outer_size,
        archive_member_count=member_count,
        directory_count=len(directories),
        regular_file_count=len(files),
        total_regular_bytes=total_regular_bytes,
        manifest_sha256=files[MANIFEST_RELATIVE_PATH].sha256,
        payload_tree_digest=tree_digest,
        payload_file_count=payload_count,
        payload_total_bytes=payload_bytes,
        archived_files=tuple(files[path] for path in sorted(files)),
        archived_directories=tuple(sorted(directories)),
    )


def _copy_pinned_artifact(
    source: Path, destination: Path, contract: LegacyArtifactContract
) -> None:
    try:
        with _open_regular_nofollow(source) as input_file:
            source_metadata = os.fstat(input_file.fileno())
            if source_metadata.st_size != contract.artifact_size_bytes:
                _fail(LegacyErrorCode.ARTIFACT_IDENTITY_MISMATCH, "copy source size")
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | O_NOFOLLOW,
                0o400,
            )
            try:
                digest = hashlib.sha256()
                copied = 0
                while True:
                    chunk = input_file.read(128 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > contract.artifact_size_bytes:
                        _fail(LegacyErrorCode.ARTIFACT_IDENTITY_MISMATCH, "copy grew")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(descriptor, view)
                        view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if (
                copied != contract.artifact_size_bytes
                or digest.hexdigest() != contract.artifact_sha256
            ):
                _fail(LegacyErrorCode.ARTIFACT_IDENTITY_MISMATCH, "copy digest")
    except LegacyRunnerError:
        raise
    except OSError as error:
        raise LegacyRunnerError(LegacyErrorCode.STAGING_FAILED, str(error)) from error


def _destination_for(
    stage_parent: Path, contract: LegacyArtifactContract, relative: str
) -> Path:
    destination = stage_parent / contract.top_level_directory
    if relative:
        destination = destination.joinpath(*PurePosixPath(relative).parts)
    try:
        destination.relative_to(stage_parent)
    except ValueError as error:
        raise LegacyRunnerError(LegacyErrorCode.INTERNAL_INVARIANT, relative) from error
    return destination


def _extract_verified_archive(
    private_archive: Path,
    stage_parent: Path,
    verified: VerifiedLegacyArtifact,
    contract: LegacyArtifactContract,
) -> Path:
    expected_files = {item.relative_path: item for item in verified.archived_files}
    expected_directories = set(verified.archived_directories)
    seen_files: set[str] = set()
    seen_directories: set[str] = set()
    file_modes: dict[Path, int] = {}
    directories: set[Path] = set()
    try:
        with _open_regular_nofollow(private_archive) as artifact:
            archive = tarfile.open(fileobj=artifact, mode="r:gz")
            with archive:
                for member in archive:
                    relative = _member_relative_path(member, contract)
                    destination = _destination_for(stage_parent, contract, relative)
                    if member.isdir():
                        if (
                            relative not in expected_directories
                            or relative in seen_directories
                        ):
                            _fail(
                                LegacyErrorCode.STAGING_FAILED,
                                f"directory drift: {relative}",
                            )
                        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                        directories.add(destination)
                        seen_directories.add(relative)
                        continue
                    expected = expected_files.get(relative)
                    if expected is None or relative in seen_files:
                        _fail(LegacyErrorCode.STAGING_FAILED, f"file drift: {relative}")
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    directories.add(destination.parent)
                    descriptor = os.open(
                        destination,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_CLOEXEC
                        | O_NOFOLLOW,
                        0o600,
                    )
                    digest = hashlib.sha256()
                    written_total = 0
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        os.close(descriptor)
                        _fail(
                            LegacyErrorCode.STAGING_FAILED, f"cannot read: {relative}"
                        )
                    try:
                        while True:
                            chunk = extracted.read(128 * 1024)
                            if not chunk:
                                break
                            written_total += len(chunk)
                            if written_total > expected.size:
                                _fail(
                                    LegacyErrorCode.STAGING_FAILED,
                                    f"size grew: {relative}",
                                )
                            digest.update(chunk)
                            view = memoryview(chunk)
                            while view:
                                written = os.write(descriptor, view)
                                view = view[written:]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    if (
                        written_total != expected.size
                        or digest.hexdigest() != expected.sha256
                    ):
                        _fail(
                            LegacyErrorCode.STAGING_FAILED, f"digest drift: {relative}"
                        )
                    file_modes[destination] = expected.mode & ~0o222
                    seen_files.add(relative)
    except LegacyRunnerError:
        raise
    except (OSError, EOFError, tarfile.TarError) as error:
        raise LegacyRunnerError(LegacyErrorCode.STAGING_FAILED, str(error)) from error

    if seen_files != set(expected_files) or seen_directories != expected_directories:
        _fail(LegacyErrorCode.STAGING_FAILED, "incomplete extraction")
    for path, mode in file_modes.items():
        os.chmod(path, mode)
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        os.chmod(path, 0o555)
    root = stage_parent / contract.top_level_directory
    if not root.is_dir():
        _fail(LegacyErrorCode.STAGING_FAILED, "stage root missing")
    return root


@contextlib.contextmanager
def staged_frozen_artifact(
    artifact_path: Path = DEFAULT_ARTIFACT_PATH,
    contract: LegacyArtifactContract = FROZEN_CONTRACT,
) -> Iterator[LegacyStage]:
    """Yield a private verified mode-hardened stage, then remove it completely."""

    with tempfile.TemporaryDirectory(prefix="sley2-legacy-stage-") as temporary:
        temporary_root = Path(temporary)
        private_archive = temporary_root / "frozen-artifact.tar.gz"
        stage_parent = temporary_root / "stage"
        scratch = temporary_root / "scratch"
        stage_parent.mkdir(mode=0o700)
        scratch.mkdir(mode=0o700)
        (scratch / "home").mkdir(mode=0o700)
        (scratch / "tmp").mkdir(mode=0o700)
        _copy_pinned_artifact(Path(artifact_path), private_archive, contract)
        verified_private = verify_frozen_artifact(private_archive, contract)
        verified = VerifiedLegacyArtifact(
            source_path=Path(artifact_path),
            artifact_sha256=verified_private.artifact_sha256,
            artifact_size_bytes=verified_private.artifact_size_bytes,
            archive_member_count=verified_private.archive_member_count,
            directory_count=verified_private.directory_count,
            regular_file_count=verified_private.regular_file_count,
            total_regular_bytes=verified_private.total_regular_bytes,
            manifest_sha256=verified_private.manifest_sha256,
            payload_tree_digest=verified_private.payload_tree_digest,
            payload_file_count=verified_private.payload_file_count,
            payload_total_bytes=verified_private.payload_total_bytes,
            archived_files=verified_private.archived_files,
            archived_directories=verified_private.archived_directories,
        )
        stage_root = _extract_verified_archive(
            private_archive, stage_parent, verified, contract
        )
        yield LegacyStage(stage_root, scratch, verified)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _bounded_command(
    executable: Path,
    stage: LegacyStage,
    contract: LegacyArtifactContract,
    *,
    timeout_seconds: float,
    output_limit_bytes: int,
) -> dict[str, Any]:
    if executable != stage.root / "bin/sley":
        _fail(LegacyErrorCode.COMMAND_NOT_ALLOWED, "executable")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > 120
    ):
        _fail(LegacyErrorCode.COMMAND_NOT_ALLOWED, "timeout")
    if (
        isinstance(output_limit_bytes, bool)
        or not isinstance(output_limit_bytes, int)
        or output_limit_bytes < 1_024
        or output_limit_bytes > 1024 * 1024
    ):
        _fail(LegacyErrorCode.COMMAND_NOT_ALLOWED, "output limit")

    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(stage.scratch / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SLEY_DISABLE_SOURCE_CACHE": "0",
        "SLEY_SOURCE_CACHE_DIR": str(stage.scratch / "source-cache"),
        "TMPDIR": str(stage.scratch / "tmp"),
        "TZ": "UTC",
    }
    argv = [str(executable), *VERSION_ARGUMENTS]
    started_at = _utc_second()
    started_monotonic = time.monotonic()
    stdout_data = bytearray()
    stderr_data = bytearray()
    output_digests = {
        "stdout": hashlib.sha256(),
        "stderr": hashlib.sha256(),
    }
    output_counts = {"stdout": 0, "stderr": 0}
    termination_reason: str | None = None
    spawn_error: str | None = None
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    streams: dict[int, tuple[str, Any]] = {}
    deadline = started_monotonic + timeout_seconds
    try:
        process = subprocess.Popen(
            argv,
            cwd=stage.root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
        if process.stdout is None or process.stderr is None:
            _fail(LegacyErrorCode.INTERNAL_INVARIANT, "command pipes")
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
            streams[stream.fileno()] = (name, stream)

        while streams:
            now = time.monotonic()
            if termination_reason is None and now >= deadline:
                termination_reason = "timeout"
                _kill_process_group(process)
            events = selector.select(timeout=max(0.0, min(0.05, deadline - now)))
            if not events and process.poll() is not None:
                events = [
                    (type("ReadyKey", (), {"fileobj": stream, "data": name})(), None)
                    for name, stream in streams.values()
                ]
            for key, _ in events:
                stream = key.fileobj
                name = key.data
                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    with contextlib.suppress(Exception):
                        selector.unregister(stream)
                    streams.pop(stream.fileno(), None)
                    stream.close()
                    continue
                output_counts[name] += len(chunk)
                output_digests[name].update(chunk)
                retained_total = len(stdout_data) + len(stderr_data)
                remaining = max(0, output_limit_bytes - retained_total)
                target = stdout_data if name == "stdout" else stderr_data
                target.extend(chunk[:remaining])
                if (
                    termination_reason is None
                    and output_counts["stdout"] + output_counts["stderr"]
                    > output_limit_bytes
                ):
                    termination_reason = "output_limit"
                    _kill_process_group(process)
        return_code = process.wait(timeout=1)
    except LegacyRunnerError:
        if process is not None:
            _kill_process_group(process)
            with contextlib.suppress(Exception):
                process.wait(timeout=1)
        raise
    except (OSError, subprocess.SubprocessError) as error:
        spawn_error = str(error)
        if process is not None:
            _kill_process_group(process)
            with contextlib.suppress(Exception):
                process.wait(timeout=1)
        return_code = process.returncode if process is not None else None
    finally:
        selector.close()
        for _, stream in streams.values():
            with contextlib.suppress(Exception):
                stream.close()

    ended_at = _utc_second()
    duration_ms = max(0, round((time.monotonic() - started_monotonic) * 1_000))
    if spawn_error is not None:
        status = "spawn_failure"
        failure_code = LegacyErrorCode.COMMAND_FAILED.symbol
    elif termination_reason == "timeout":
        status = "timeout"
        failure_code = LegacyErrorCode.COMMAND_TIMEOUT.symbol
    elif termination_reason == "output_limit":
        status = "output_limit"
        failure_code = LegacyErrorCode.COMMAND_OUTPUT_LIMIT.symbol
    elif return_code != 0:
        status = "failed"
        failure_code = LegacyErrorCode.COMMAND_FAILED.symbol
    else:
        status = "completed"
        failure_code = None

    expected_stdout = (contract.expected_version_output + "\n").encode("utf-8")
    exact_version_match = (
        status == "completed"
        and return_code == 0
        and bytes(stdout_data) == expected_stdout
        and output_counts["stdout"] == len(expected_stdout)
        and output_counts["stderr"] == 0
    )
    if status == "completed" and not exact_version_match:
        status = "failed"
        failure_code = LegacyErrorCode.COMMAND_FAILED.symbol

    def output_report(name: str, retained: bytearray) -> dict[str, Any]:
        count = output_counts[name]
        return {
            "byte_count": count,
            "sha256": output_digests[name].hexdigest(),
            "retained_prefix_base64": base64.b64encode(bytes(retained)).decode("ascii"),
            "retained_prefix_bytes": len(retained),
            "truncated": len(retained) != count,
        }

    return {
        "command_id": "version_smoke",
        "argv": argv,
        "relative_argv": ["bin/sley", *VERSION_ARGUMENTS],
        "working_directory": str(stage.root),
        "environment": environment,
        "environment_sha256": hashlib.sha256(
            canonical_json_bytes(environment)
        ).hexdigest(),
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "duration_ms": duration_ms,
        "timeout_seconds": timeout_seconds,
        "output_limit_bytes": output_limit_bytes,
        "status": status,
        "failure_code": failure_code,
        "spawn_error": spawn_error,
        "return_code": return_code,
        "stdout": output_report("stdout", stdout_data),
        "stderr": output_report("stderr", stderr_data),
        "expected_stdout": contract.expected_version_output + "\n",
        "exact_version_match": exact_version_match,
        "success": exact_version_match,
    }


def run_version_smoke(
    artifact_path: Path = DEFAULT_ARTIFACT_PATH,
    contract: LegacyArtifactContract = FROZEN_CONTRACT,
    *,
    timeout_seconds: float = 90.0,
    output_limit_bytes: int = 64 * 1024,
) -> dict[str, Any]:
    """Run and retain the only allowed S20-600 executable smoke."""

    attempt_started = _utc_second()
    try:
        with staged_frozen_artifact(artifact_path, contract) as stage:
            execution = _bounded_command(
                stage.root / "bin/sley",
                stage,
                contract,
                timeout_seconds=timeout_seconds,
                output_limit_bytes=output_limit_bytes,
            )
            verification = stage.verified.report()
    except LegacyRunnerError as error:
        return {
            "contract": SMOKE_CONTRACT,
            "work_package": "S20-600",
            "scope": EVIDENCE_SCOPE,
            "attempt_started_at_utc": attempt_started,
            "attempt_ended_at_utc": _utc_second(),
            "artifact_path": str(artifact_path),
            "success": False,
            "status": "harness_failure",
            "failure_code": error.code.symbol,
            "failure_detail": error.detail,
            "verification": None,
            "execution": None,
            "disposable_private_copy": True,
            "stage_write_bits_removed": True,
            "read_only_mount_enforced": False,
            "network_isolation": "NOT_ENFORCED_VERSION_ONLY",
            "provider_or_model_execution": False,
            "benchmark_trials_executed": 0,
            "live_legacy_checkout_interaction": False,
            "full_s20_600_complete": False,
        }
    return {
        "contract": SMOKE_CONTRACT,
        "work_package": "S20-600",
        "scope": EVIDENCE_SCOPE,
        "attempt_started_at_utc": attempt_started,
        "attempt_ended_at_utc": _utc_second(),
        "artifact_path": str(artifact_path),
        "success": execution["success"],
        "status": execution["status"],
        "failure_code": execution["failure_code"],
        "failure_detail": execution["spawn_error"],
        "verification": verification,
        "execution": execution,
        "disposable_private_copy": True,
        "stage_write_bits_removed": True,
        "read_only_mount_enforced": False,
        "network_isolation": "NOT_ENFORCED_VERSION_ONLY",
        "provider_or_model_execution": False,
        "benchmark_trials_executed": 0,
        "live_legacy_checkout_interaction": False,
        "full_s20_600_complete": False,
    }


def record_smoke_evidence(evidence_directory: Path, report: Mapping[str, Any]) -> Path:
    """Create one immutable attempt file; never rewrite or delete earlier failures."""

    try:
        directory = Path(evidence_directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = canonical_json_bytes(report) + b"\n"
        digest = hashlib.sha256(payload).hexdigest()
        timestamp = str(report.get("attempt_started_at_utc", "unknown"))
        timestamp = re.sub(r"[^0-9A-Za-z]+", "", timestamp) or "unknown"
        target = directory / f"smoke-{timestamp}-{digest[:16]}.json"
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | O_NOFOLLOW,
            0o600,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory_descriptor = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return target
    except FileExistsError as error:
        raise LegacyRunnerError(
            LegacyErrorCode.EVIDENCE_WRITE_FAILED, "duplicate evidence"
        ) from error
    except OSError as error:
        raise LegacyRunnerError(
            LegacyErrorCode.EVIDENCE_WRITE_FAILED, str(error)
        ) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify", "smoke"))
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT_PATH)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=90.0)
    parser.add_argument("--output-limit-bytes", type=int, default=64 * 1024)
    arguments = parser.parse_args()

    if arguments.command == "verify":
        try:
            report = verify_frozen_artifact(arguments.artifact).report()
            report["result"] = "PASS"
            status = 0
        except LegacyRunnerError as error:
            report = {
                "contract": VERIFICATION_CONTRACT,
                "source_path": str(arguments.artifact),
                "failure_code": error.code.symbol,
                "failure_detail": error.detail,
                "result": "FAIL",
            }
            status = 1
    else:
        report = run_version_smoke(
            arguments.artifact,
            timeout_seconds=arguments.timeout_seconds,
            output_limit_bytes=arguments.output_limit_bytes,
        )
        status = 0 if report["success"] else 1
        if arguments.evidence_dir is not None:
            try:
                report["evidence_path"] = str(
                    record_smoke_evidence(arguments.evidence_dir, report)
                )
            except LegacyRunnerError as error:
                report["evidence_failure_code"] = error.code.symbol
                report["evidence_failure_detail"] = error.detail
                status = 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
