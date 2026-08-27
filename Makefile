.PHONY: quick core conformance adversarial fuzz-smoke v2 release-check check-changed

quick:
	python3 scripts/check_m0.py
	python3 scripts/check_benchmark_baseline.py
	python3 scripts/check_scb1_spec.py
	cargo fmt --all -- --check
	cargo check --workspace --locked
	cargo test --workspace --locked

conformance:
	python3 scripts/check_scb1_spec.py
	python3 scripts/check_oracle_independence.py
	cargo test -p sley-scb1 --locked
	uv run --project oracle/scb1 --frozen python -m unittest discover -s oracle/scb1/tests -v
	uv run --project oracle/scb1 --frozen sley2-scb1-oracle check --accepted conformance/scb1/v1/accepted.json --rejected conformance/scb1/v1/rejected.json

check-changed: quick conformance
	@python3 scripts/check_changed.py

core adversarial fuzz-smoke v2 release-check:
	@python3 scripts/gate_status.py $@
