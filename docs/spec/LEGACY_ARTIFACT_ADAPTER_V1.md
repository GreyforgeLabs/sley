# Frozen Legacy Artifact Adapter v1

Status: S20-600 verified-artifact and version-smoke contract only.

## Boundary

This contract admits exactly the frozen Sley 1.2.0 Linux x86_64
release-candidate archive as an external comparison artifact. It supplies a
secure artifact adapter and one executable version smoke. It is not the full
S20-600 legacy trial runner.

The adapter contains no model or provider call, benchmark task mapper,
workspace fixture, semantic oracle, trial scheduler, accounting path, network
isolation mechanism, or promotion path. It executes zero benchmark trials.
The live Sley 1.2 checkout is outside its authority and remains untouched.

## Pinned identity

Admission requires all of the following exact values before archive parsing:

- path default
  `<LOCAL_HOME>/archive/sley/1.2.0/sley-1.2.0-linux-x86_64.tar.gz`;
- SHA-256
  `b24f19c6a348751c93c9cf63f6f4154f6132796112c26f9d8c0e71324080dbc7`;
- size 4,611,024 bytes;
- release `1.2.0` and artifact ID `sley-1.2.0-linux-x86_64`;
- source commit `397fa28ded15ddbeca5404ee00a3f5bd5546b296` with `dirty=false`;
- payload tree digest
  `sha256:548e0057c0b1543b0c926051beb085653942ccddba93e6b60864382321a4d8de`;
- `bin/sley` SHA-256
  `c9d56feeb575653aff7c9cabf629902a307b18af1542248292cf0ce278843d6c`.

The open artifact file descriptor is hashed before the same descriptor is
rewound for parsing. A stage first copies those exact bytes into a private
temporary directory and verifies the private copy again. This prevents path
replacement between admission and extraction.

## Archive and manifest verification

The verifier accepts only regular files and directories under the one exact
top-level directory. It rejects absolute paths, dot or parent traversal,
backslashes, non-normalized names, duplicates, special permission bits,
symbolic links, hard links, devices, FIFOs, sockets, unsupported member types,
and any member, count, or byte total beyond the frozen bounds. The actual
archive has exactly 1,568 members: 498 directories and 1,070 regular files.

JSON parsing rejects duplicate keys. The embedded manifest must retain local
release-candidate-only, unsigned, non-publication authority and the exact Linux
x86_64 tar.gz platform. Its metadata inventory is exactly the license list,
manifest, and SPDX SBOM. Its 1,067 sorted payload entries and 8,610,725 payload
bytes must match archive path, mode, size, and SHA-256 one by one. The archive
may not add unmanifested payload bytes or release metadata.

Extraction is manual. `tarfile.extract` and `extractall` are forbidden. Files
are created exclusively inside a new private tree, rehashed while written, and
then have every write bit removed. Temporary mutable HOME, TMPDIR, and
source-cache paths are separate from that tree and disappear with the stage.
This mode hardening is not a read-only mount: the same owning UID could change
modes. That limitation is acceptable only for the exact trusted version smoke
and is explicitly insufficient for a benchmark trial.

## Executable smoke and evidence

The only allowed executable and arguments are staged `bin/sley --version`.
`subprocess.Popen` receives an argv array with `shell=false`, closed file
descriptors, no stdin, an exact non-inherited environment, and a new process
session. The source-task cache is allowed only inside disposable scratch
storage. The default timeout is 90 seconds, the hard timeout maximum is 120
seconds, and the default combined retained-output cap is 65,536 bytes.

Timeout or output overflow kills the complete process group. Success requires
exit zero, exact stdout `sley 1.2.0\n`, and empty stderr. Every result preserves
the exact argv, working directory, environment and its digest, timestamps,
duration, return code, stdout/stderr byte counts and digests, retained prefixes,
truncation state, timeout, and failure code. Evidence files are canonical JSON,
create-only, fsynced attempts. No rewrite or delete API exists.

The environment does not enforce network isolation. This is explicitly
recorded as `NOT_ENFORCED_VERSION_ONLY`; the allowed command is version-only and
does not establish trial containment. Provider/model execution, benchmark
trials, succession metrics, and public claims remain false or zero.

## Stable failures

Numeric codes 60000 through 60014 are frozen as
`LEGACY_ARTIFACT_MISSING`, `LEGACY_ARTIFACT_IDENTITY_MISMATCH`,
`LEGACY_ARCHIVE_INVALID`, `LEGACY_ARCHIVE_MEMBER_UNSAFE`,
`LEGACY_ARCHIVE_LIMIT_EXCEEDED`, `LEGACY_MANIFEST_INVALID`,
`LEGACY_MANIFEST_IDENTITY_MISMATCH`, `LEGACY_PAYLOAD_MISMATCH`,
`LEGACY_STAGING_FAILED`, `LEGACY_COMMAND_NOT_ALLOWED`,
`LEGACY_COMMAND_TIMEOUT`, `LEGACY_COMMAND_OUTPUT_LIMIT`,
`LEGACY_COMMAND_FAILED`, `LEGACY_EVIDENCE_WRITE_FAILED`, and
`LEGACY_INTERNAL_INVARIANT`.

## Explicit gaps

Full S20-600 remains open. A real legacy-arm trial still requires an approved
frozen run manifest, representation-neutral task-to-fixture mapping, disposable
task workspace, network containment, exact provider/model adapter, strict
oracle, complete tool trace, every-attempt retention, and cross-arm fairness.
Those missing surfaces cannot be inferred from a successful version smoke.
