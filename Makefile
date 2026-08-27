.PHONY: quick core conformance adversarial fuzz-smoke v2 release-check check-changed

quick:
	python3 scripts/check_m0.py
	cargo metadata --no-deps --format-version 1 >/dev/null

check-changed: quick
	@python3 scripts/check_changed.py

core conformance adversarial fuzz-smoke v2 release-check:
	@python3 scripts/gate_status.py $@
