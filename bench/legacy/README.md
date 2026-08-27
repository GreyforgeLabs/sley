# Frozen legacy artifact adapter

`bench/legacy` is the scoped S20-600 adapter for the frozen Sley 1.2.0 Linux
x86_64 release-candidate archive. It verifies the pinned outer hash and size,
rejects unsafe archive structure, verifies the embedded release identity and
every payload byte, copies the archive into a private temporary directory, and
manually extracts it into a write-bit-stripped disposable tree.

The only executable command is the exact staged `bin/sley --version` smoke.
It uses no shell interpolation, no inherited environment, no stdin, a bounded
timeout, bounded retained output, a private HOME/TMPDIR/source cache, and a new
process session. Each requested evidence record is create-only. Timeouts,
output-limit kills, spawn failures, nonzero exits, stdout, stderr, environment,
and successful results use the same evidence path.

Routine verification and synthetic adversarial smokes:

```text
python3 scripts/check_legacy_runner.py
```

Explicit real frozen-artifact smoke, which can take about one minute on this
machine:

```text
make legacy-runner-smoke
```

Runtime attempts are retained under
`evidence/runtime/s20-600-legacy-smoke/`, which is intentionally ignored by
Git. The adapter does not execute benchmark tasks, models, providers, oracles,
or Sley 2. POSIX modes remove write bits, but no read-only mount or network
namespace is enforced, so this cannot support a benchmark-trial containment
claim. It never reads or writes the separately owned live Sley 1.2 checkout.
