.PHONY: quick core conformance adversarial fuzz-smoke v2 release-check check-changed

quick:
	python3 scripts/check_m0.py
	python3 scripts/check_benchmark_baseline.py
	python3 scripts/check_scb1_spec.py
	cargo fmt --all -- --check
	cargo check --workspace --locked
	cargo test -p sley-id --locked

check-changed: quick
	@python3 scripts/check_changed.py

core conformance adversarial fuzz-smoke v2 release-check:
	@python3 scripts/gate_status.py $@
