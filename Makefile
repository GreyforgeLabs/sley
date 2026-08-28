.PHONY: quick core conformance adversarial fuzz-smoke legacy-runner-smoke scb1-persistent-fuzz-smoke schema-persistent-fuzz-smoke pack-persistent-fuzz-smoke semantic-checkers-persistent-fuzz-smoke query-persistent-fuzz-smoke vm-persistent-fuzz-smoke adapter-responses-persistent-fuzz-smoke mutation-candidate-persistent-fuzz-smoke v2 release-check check-changed

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
	python3 scripts/check_report_envelope_profile.py
	python3 scripts/check_index_snapshot_profile.py
	python3 scripts/check_restricted_query_profile.py
	python3 scripts/check_restricted_query_capsule_profile.py
	python3 scripts/check_mutation_schema.py
	python3 scripts/check_mutation_value_codecs.py
	python3 scripts/check_mutation_candidate_persistent_fuzz_slice.py
	python3 scripts/check_policy_root.py
	python3 scripts/check_capability_token.py
	python3 scripts/check_legacy_runner.py
	python3 scripts/check_raw_baseline_runner.py
	python3 scripts/check_external_comparison_availability.py
	python3 scripts/check_supply_chain_audit.py
	python3 scripts/check_schema_fuzz_slice.py
	python3 scripts/check_s20_700_frontier.py
	python3 scripts/check_local_completion_frontier.py
	python3 scripts/check_candidate_contract_freeze.py
	python3 scripts/check_candidate_result_contract.py
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
	uv run --project oracle/scb1 --frozen sley2-scb1-oracle check-mutation-value --accepted conformance/mutation-value/v1/accepted.json --rejected conformance/mutation-value/v1/rejected.json
	uv run --project oracle/scb1 --frozen sley2-scb1-oracle check-mutation-candidate --accepted conformance/mutation-candidate/v1/accepted.json --rejected conformance/mutation-candidate/v1/rejected.json
	uv run --project oracle/scb1 --frozen python scripts/check_schema_epoch_vector.py
	uv run --project oracle/scb1 --frozen python scripts/check_state_root_vector.py
	uv run --project oracle/scb1 --frozen python scripts/check_repository_pack_vector.py

adversarial:
	cargo test -p sley-mutate mutation_value_codec_adversarial --locked
	cargo test -p sley-store --locked
	cargo test -p sley-repo --locked
	cargo test -p sley-adapter authorized_adapter_request_binding_confusion_fails_before_charge --locked
	python3 scripts/check_m1_gate.py adversarial

fuzz-smoke:
	cargo test -p sley-mutate bounded_mutation_value_codec_fuzz_smoke --locked
	cargo test -p sley-scb1 bounded_scb1_decoder_fuzz_smoke --locked
	cargo test -p sley-schema bounded_schema_bootstrap_import_fuzz_smoke --locked
	cargo test -p sley-store randomized_invalid_records_never_promote --locked
	cargo test -p sley-repo bounded_pack_import_fuzz_smoke --locked
	python3 scripts/check_m1_gate.py fuzz-smoke

legacy-runner-smoke:
	python3 -m bench.legacy.runner smoke --timeout-seconds 90 --output-limit-bytes 65536 --evidence-dir evidence/runtime/s20-600-legacy-smoke

scb1-persistent-fuzz-smoke:
	python3 scripts/check_scb1_persistent_fuzz_slice.py
	python3 scripts/run_scb1_persistent_fuzz.py

schema-persistent-fuzz-smoke:
	python3 scripts/check_schema_persistent_fuzz_slice.py
	python3 scripts/run_schema_persistent_fuzz.py

pack-persistent-fuzz-smoke:
	python3 scripts/check_pack_persistent_fuzz_slice.py
	python3 scripts/run_pack_persistent_fuzz.py

semantic-checkers-persistent-fuzz-smoke:
	python3 scripts/check_semantic_checkers_persistent_fuzz_slice.py
	python3 scripts/run_semantic_checkers_persistent_fuzz.py

query-persistent-fuzz-smoke:
	python3 scripts/check_query_persistent_fuzz_slice.py
	python3 scripts/run_query_persistent_fuzz.py

vm-persistent-fuzz-smoke:
	python3 scripts/check_vm_persistent_fuzz_slice.py
	python3 scripts/run_vm_persistent_fuzz.py

adapter-responses-persistent-fuzz-smoke:
	python3 scripts/check_adapter_responses_persistent_fuzz_slice.py
	python3 scripts/run_adapter_responses_persistent_fuzz.py

mutation-candidate-persistent-fuzz-smoke:
	python3 scripts/check_mutation_candidate_persistent_fuzz_slice.py
	python3 scripts/run_mutation_candidate_persistent_fuzz.py

check-changed: quick core conformance adversarial fuzz-smoke
	@python3 scripts/check_changed.py

v2 release-check:
	@python3 scripts/gate_status.py $@
