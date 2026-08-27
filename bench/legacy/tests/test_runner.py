from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path

from bench.legacy.runner import (
    LegacyArtifactContract,
    LegacyErrorCode,
    LegacyRunnerError,
    record_smoke_evidence,
    run_version_smoke,
    staged_frozen_artifact,
    verify_frozen_artifact,
)


TOP = "synthetic-sley-1.2.0-linux-x86_64"
RELEASE = "1.2.0"
COMMIT = "1" * 40


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _manifest(payload_files: dict[str, tuple[bytes, int]]) -> tuple[dict, str]:
    records = [
        {
            "digest": f"sha256:{_digest(payload)}",
            "mode": f"{mode:04o}",
            "path": path,
            "size": len(payload),
        }
        for path, (payload, mode) in sorted(payload_files.items())
    ]
    tree_digest = "sha256:" + _digest(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    )
    manifest = {
        "schema": "sley.release.manifest.v1",
        "artifact_id": TOP,
        "release": RELEASE,
        "status": "release_candidate",
        "source": {
            "commit": COMMIT,
            "dirty": False,
            "payload_tree_digest": tree_digest,
        },
        "authority": {
            "mode": "local_release_candidate_only",
            "publication_authorized": False,
            "signing_status": "unsigned",
            "tag_authorized": False,
            "upload_authorized": False,
        },
        "platform": {
            "architecture": "x86_64",
            "archive_format": "tar.gz",
            "os": "linux",
            "support_status": "supported",
        },
        "metadata": {
            "license_inventory": "release/licenses.json",
            "manifest": "release/manifest.json",
            "sbom": "release/sbom.spdx.json",
        },
        "toolchain": {"sley_version": "sley 1.2.0"},
        "payload": {
            "file_count": len(records),
            "files": records,
            "inventory_scope": "tracked_release_payload_excluding_release_metadata",
            "total_bytes": sum(record["size"] for record in records),
        },
    }
    return manifest, tree_digest


def _add_directory(archive: tarfile.TarFile, name: str) -> None:
    member = tarfile.TarInfo(name + "/")
    member.type = tarfile.DIRTYPE
    member.mode = 0o755
    member.mtime = 0
    archive.addfile(member)


def _add_file(archive: tarfile.TarFile, name: str, payload: bytes, mode: int) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = mode
    member.mtime = 0
    archive.addfile(member, io.BytesIO(payload))


def build_artifact(
    path: Path,
    script: bytes,
    *,
    corrupt_payload: bool = False,
    unsafe_kind: str | None = None,
) -> LegacyArtifactContract:
    payload_files = {
        "bin/sley": (script, 0o755),
        "fixture.txt": (b"frozen fixture\n", 0o644),
    }
    manifest, tree_digest = _manifest(payload_files)
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode() + b"\n"
    archive_payloads = {
        "bin/sley": (script, 0o755),
        "fixture.txt": (
            b"corrupt fixture\n" if corrupt_payload else b"frozen fixture\n",
            0o644,
        ),
        "release/licenses.json": (b"{}\n", 0o644),
        "release/manifest.json": (manifest_bytes, 0o644),
        "release/sbom.spdx.json": (b"{}\n", 0o644),
    }
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for directory in (TOP, f"{TOP}/bin", f"{TOP}/release"):
            _add_directory(archive, directory)
        for relative, (payload, mode) in sorted(archive_payloads.items()):
            _add_file(archive, f"{TOP}/{relative}", payload, mode)
        if unsafe_kind == "traversal":
            _add_file(archive, f"{TOP}/../escape", b"escape\n", 0o644)
        elif unsafe_kind == "symlink":
            member = tarfile.TarInfo(f"{TOP}/escape-link")
            member.type = tarfile.SYMTYPE
            member.linkname = "/tmp/escape"
            member.mode = 0o777
            archive.addfile(member)
        elif unsafe_kind == "duplicate":
            _add_file(archive, f"{TOP}/fixture.txt", b"duplicate\n", 0o644)
    artifact_bytes = path.read_bytes()
    return LegacyArtifactContract(
        artifact_sha256=_digest(artifact_bytes),
        artifact_size_bytes=len(artifact_bytes),
        top_level_directory=TOP,
        release=RELEASE,
        source_commit=COMMIT,
        artifact_id=TOP,
        expected_version_output="sley 1.2.0",
        payload_tree_digest=tree_digest,
        expected_sley_digest=_digest(script),
        max_archive_members=32,
        max_regular_files=16,
        max_total_regular_bytes=256 * 1024,
        max_member_bytes=128 * 1024,
        max_manifest_bytes=64 * 1024,
    )


SUCCESS_SCRIPT = b"#!/bin/sh\nprintf 'sley 1.2.0\\n'\n"


class LegacyRunnerTests(unittest.TestCase):
    def test_valid_artifact_is_verified_stage_write_bits_removed_and_smoked(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.tar.gz"
            contract = build_artifact(artifact, SUCCESS_SCRIPT)
            verified = verify_frozen_artifact(artifact, contract)
            self.assertTrue(verified.report()["payload_inventory_verified"])
            self.assertEqual(verified.payload_file_count, 2)

            with staged_frozen_artifact(artifact, contract) as stage:
                stage_root = stage.root
                self.assertFalse(stat.S_IMODE(stage.root.stat().st_mode) & 0o222)
                self.assertFalse(
                    stat.S_IMODE((stage.root / "fixture.txt").stat().st_mode) & 0o222
                )
                self.assertTrue(os.access(stage.scratch, os.W_OK))
            self.assertFalse(stage_root.exists())

            report = run_version_smoke(artifact, contract, timeout_seconds=2.0)
            self.assertTrue(report["success"])
            self.assertEqual(report["execution"]["return_code"], 0)
            self.assertEqual(report["benchmark_trials_executed"], 0)

    def test_outer_identity_drift_fails_before_archive_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.tar.gz"
            contract = build_artifact(artifact, SUCCESS_SCRIPT)
            with artifact.open("ab") as output:
                output.write(b"drift")
            with self.assertRaises(LegacyRunnerError) as caught:
                verify_frozen_artifact(artifact, contract)
            self.assertEqual(
                caught.exception.code, LegacyErrorCode.ARTIFACT_IDENTITY_MISMATCH
            )

    def test_traversal_links_and_duplicates_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for unsafe_kind in ("traversal", "symlink", "duplicate"):
                with self.subTest(unsafe_kind=unsafe_kind):
                    artifact = Path(temporary) / f"{unsafe_kind}.tar.gz"
                    contract = build_artifact(
                        artifact, SUCCESS_SCRIPT, unsafe_kind=unsafe_kind
                    )
                    with self.assertRaises(LegacyRunnerError) as caught:
                        verify_frozen_artifact(artifact, contract)
                    self.assertEqual(
                        caught.exception.code, LegacyErrorCode.ARCHIVE_MEMBER_UNSAFE
                    )

    def test_payload_tamper_fails_manifest_inventory_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.tar.gz"
            contract = build_artifact(artifact, SUCCESS_SCRIPT, corrupt_payload=True)
            with self.assertRaises(LegacyRunnerError) as caught:
                verify_frozen_artifact(artifact, contract)
            self.assertEqual(caught.exception.code, LegacyErrorCode.PAYLOAD_MISMATCH)

    def test_timeout_is_returned_as_retained_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.tar.gz"
            contract = build_artifact(artifact, b"#!/bin/sh\nsleep 2\n")
            report = run_version_smoke(artifact, contract, timeout_seconds=0.05)
            self.assertFalse(report["success"])
            self.assertEqual(report["status"], "timeout")
            self.assertEqual(report["failure_code"], "LEGACY_COMMAND_TIMEOUT")
            self.assertEqual(report["execution"]["return_code"], -9)

    def test_nonzero_exit_and_stderr_are_retained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.tar.gz"
            script = b"#!/bin/sh\nprintf 'frozen failure\\n' >&2\nexit 7\n"
            contract = build_artifact(artifact, script)
            report = run_version_smoke(artifact, contract, timeout_seconds=2.0)
            self.assertFalse(report["success"])
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["execution"]["return_code"], 7)
            self.assertEqual(report["execution"]["stderr"]["byte_count"], 15)
            self.assertFalse(report["execution"]["stderr"]["truncated"])

    def test_output_limit_kills_and_retains_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.tar.gz"
            contract = build_artifact(artifact, b"#!/bin/sh\nyes X\n")
            report = run_version_smoke(
                artifact,
                contract,
                timeout_seconds=2.0,
                output_limit_bytes=1_024,
            )
            self.assertFalse(report["success"])
            self.assertEqual(report["status"], "output_limit")
            self.assertEqual(report["failure_code"], "LEGACY_COMMAND_OUTPUT_LIMIT")
            self.assertEqual(
                report["execution"]["stdout"]["retained_prefix_bytes"], 1_024
            )
            self.assertTrue(report["execution"]["stdout"]["truncated"])

    def test_nonfinite_timeout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.tar.gz"
            contract = build_artifact(artifact, SUCCESS_SCRIPT)
            report = run_version_smoke(
                artifact,
                contract,
                timeout_seconds=float("nan"),
            )
            self.assertFalse(report["success"])
            self.assertEqual(report["status"], "harness_failure")
            self.assertEqual(report["failure_code"], "LEGACY_COMMAND_NOT_ALLOWED")

    def test_evidence_records_are_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "evidence"
            first = {
                "attempt_started_at_utc": "2026-08-27T12:00:00Z",
                "status": "timeout",
            }
            second = {
                "attempt_started_at_utc": "2026-08-27T12:00:01Z",
                "status": "completed",
            }
            first_path = record_smoke_evidence(directory, first)
            first_bytes = first_path.read_bytes()
            second_path = record_smoke_evidence(directory, second)
            self.assertNotEqual(first_path, second_path)
            self.assertEqual(first_path.read_bytes(), first_bytes)
            self.assertEqual(len(list(directory.glob("*.json"))), 2)
            with self.assertRaises(LegacyRunnerError) as caught:
                record_smoke_evidence(directory, first)
            self.assertEqual(
                caught.exception.code, LegacyErrorCode.EVIDENCE_WRITE_FAILED
            )


if __name__ == "__main__":
    unittest.main()
