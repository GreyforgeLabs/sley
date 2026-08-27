.PHONY: quick core conformance adversarial fuzz-smoke v2 release-check check-changed

quick:
	python3 scripts/check_m0.py
	python3 scripts/check_benchmark_baseline.py
	python3 scripts/check_scb1_spec.py
	python3 scripts/check_schema_epoch_spec.py
	python3 scripts/check_object_store_spec.py
	python3 scripts/check_state_root_spec.py
	python3 scripts/check_repository_pack_spec.py
	python3 scripts/check_gc_spec.py
	python3 scripts/check_type_system.py
	python3 scripts/check_cfg.py
	python3 scripts/check_effect_system.py
	python3 scripts/check_contract_test_profile.py
	python3 scripts/check_fingerprint_impact_profile.py
	python3 scripts/check_vm_lowering_profile.py
	python3 scripts/check_vm_execution_profile.py
	python3 scripts/check_reference_adapter_profile.py
	cargo fmt --all -- --check
	cargo check --workspace --locked
	cargo test --workspace --locked

core:
	cargo test --workspace --locked
	python3 scripts/check_m1_gate.py core

conformance:
	python3 scripts/check_scb1_spec.py
	python3 scripts/check_oracle_independence.py
	cargo test -p sley-scb1 --locked
	cargo test -p sley-schema --locked
	cargo test -p sley-store --locked
	cargo test -p sley-state-root --locked
	cargo test -p sley-repo --locked
	uv run --project oracle/scb1 --frozen python -m unittest discover -s oracle/scb1/tests -v
	uv run --project oracle/scb1 --frozen sley2-scb1-oracle check --accepted conformance/scb1/v1/accepted.json --rejected conformance/scb1/v1/rejected.json
	uv run --project oracle/scb1 --frozen python scripts/check_schema_epoch_vector.py
	uv run --project oracle/scb1 --frozen python scripts/check_state_root_vector.py
	uv run --project oracle/scb1 --frozen python scripts/check_repository_pack_vector.py

adversarial:
	cargo test -p sley-store --locked
	cargo test -p sley-repo --locked
	python3 scripts/check_m1_gate.py adversarial

fuzz-smoke:
	cargo test -p sley-scb1 bounded_scb1_decoder_fuzz_smoke --locked
	cargo test -p sley-store randomized_invalid_records_never_promote --locked
	cargo test -p sley-repo bounded_pack_import_fuzz_smoke --locked
	python3 scripts/check_m1_gate.py fuzz-smoke

check-changed: quick core conformance adversarial fuzz-smoke
	@python3 scripts/check_changed.py

v2 release-check:
	@python3 scripts/gate_status.py $@
