.DEFAULT_GOAL := help
SHELL := /bin/bash
.SHELLFLAGS := -Eeuo pipefail -c
.ONESHELL:
.DELETE_ON_ERROR:

VENV ?= .venv
PYTHON ?= $(VENV)/bin/python
CLI ?= $(VENV)/bin/fl-forensics
STUDY ?= results/revision-episodic-attribution-recovery-v1
TON_IOT_INDEX ?=
TON_IOT_OUTPUT ?= artifacts/ton-iot-preflight
TON_IOT_PREFLIGHT ?=
TON_IOT_PROTOCOL ?=
TON_IOT_WINDOWS_OUTPUT ?= artifacts/ton-iot-windows
TON_IOT_TRANSFER ?=
TON_IOT_TARGET_WORKSPACE ?= artifacts/ton-iot-target-retraining
TON_IOT_F1_WORKSPACE ?=

DATA24_SOURCE ?= data/raw/uwf-zeekdata24/parquet
M2_AUDIT ?= artifacts/m2-data24-parquet-audit.json
M2_DATA ?= artifacts/m2-data24-parquet
M2_BASELINE ?= artifacts/m2-data24-parquet-central

M3_IID_PARTITION ?= artifacts/m3-data24-parquet-iid-local-test-v1
M3_NON_IID_PARTITION ?= artifacts/m3-data24-parquet-non-iid
M3_IID_RUN ?= artifacts/m3-data24-parquet-iid-fedavg
M3_NON_IID_RUN ?= artifacts/m3-data24-parquet-non-iid-fedavg

DEMO_INPUT ?= tests/fixtures/zeek_conn.jsonl
DEMO_WORKSPACE ?= artifacts/demo-output-make

.PHONY: help setup check doctor test lint smoke validate dataset-download m2 m3 foundation
.PHONY: guard-smoke guard-download guard-m2 guard-m3 guard-foundation

help:
	@printf '%s\n' \
	  'Repository entry points (no campaign starts by default):' \
	  '  make help              Show entry points and path variables' \
	  '' \
	  'Documentation and retained evidence:' \
	  '  make docs-check        Check maintained docs, catalogues and retained Markdown' \
	  '  make docs-index        Regenerate the two registered catalogue files' \
	  '  make evidence-list     List all retained study directories' \
	  '  make evidence-check    Check the selected stored flat checksum publication' \
	  '  make thesis-evidence   Check the evidence cited by the thesis (docs/thesis-evidence.txt)' \
	  '                         Override STUDY=results/<registered-study>' \
	  '' \
	  'Environment and verification:' \
	  '  make setup             Create .venv and install declared extras' \
	  '  make check             Check package dependencies and CLI' \
	  '  make doctor            Also check Docker Compose and OpenSSL' \
	  '  make test-docs         Run repository-checker regression tests' \
	  '  make test-formal       Run selected formal/coverage/review/replay tests' \
	  '  make test-groups       Run selected retrospective/episode/diagnostic tests' \
	  '  make test              Run the full pytest suite' \
	  '  make lint              Run documented Ruff error checks' \
	  '  make smoke             Generate and verify the small acquisition fixture' \
	  '  make validate          Run package checks, tests, lint, fixture smoke and docs-check' \
	  '' \
	  'Explicit data/foundation reconstruction:' \
	  '  make dataset-download Download pinned Data24 into a fresh DATA24_SOURCE' \
	  '  make dataset-verify   Check existing pinned source without download/write' \
	  '  make test-ton-iot     Run focused ToN-IoT source, window and novelty checks' \
	  '  make ton-iot-preflight Scan indexed official network CSVs without extraction' \
	  '                         Requires TON_IOT_INDEX and fresh TON_IOT_OUTPUT' \
	  '  make ton-iot-windows   Build declared occurrence and projection views' \
	  '                         Requires index, preflight, protocol and fresh windows output' \
	  '  make ton-iot-target-prepare  Freeze target splits and preprocessing' \
	  '  make ton-iot-target-train    Train the fixed numerical FedAvg study' \
	  '  make ton-iot-target-evaluate Evaluate after all checkpoint selections close' \
	  '  make ton-iot-target-flow-select  Correct selection using connection-end bounds' \
	  '  make ton-iot-f1-study  Run an explicit fresh validation-selected F1 assessment' \
	  '  make m2                Build and verify M2 artifacts' \
	  '  make m3                Build and verify IID/non-IID M3 baselines' \
	  '  make foundation        Run M2 then M3 (controlled source must exist)' \
	  '' \
	  'Path variables: VENV, PYTHON, CLI, STUDY, DATA24_SOURCE, M2_AUDIT, M2_DATA,' \
	  'M2_BASELINE, M3_IID_PARTITION, M3_NON_IID_PARTITION, M3_IID_RUN, M3_NON_IID_RUN,' \
	  'DEMO_INPUT, DEMO_WORKSPACE and the TON_IOT_* variables. Generation targets refuse existing outputs.' \
	  'M4-M8 and research campaign execution remains profile-specific; see docs/guide/REPRODUCIBILITY.md.'

setup:
	if [[ ! -x "$(PYTHON)" ]]; then
	  python3 -m venv "$(VENV)"
	fi
	"$(PYTHON)" -m pip install --upgrade pip
	"$(PYTHON)" -m pip install -e '.[ml,simulation,reporting,dev]'

check:
	if [[ ! -x "$(PYTHON)" ]]; then
	  printf 'Missing %s; run: make setup\n' "$(PYTHON)" >&2
	  exit 2
	fi
	if [[ ! -x "$(CLI)" ]]; then
	  printf 'Missing %s; run: make setup\n' "$(CLI)" >&2
	  exit 2
	fi
	"$(PYTHON)" -m pip check
	"$(CLI)" --help >/dev/null
	printf 'Python package and CLI are ready.\n'

doctor: check
	docker compose version
	openssl version

test: check
	"$(PYTHON)" -m pytest -q

lint: check
	"$(PYTHON)" -m ruff check --select E9,F63,F7,F82 src tests scripts/repository_audit.py

validate: test lint smoke docs-check

guard-smoke:
	if [[ ! -f "$(DEMO_INPUT)" ]]; then
	  printf 'Demo fixture not found: %s\n' "$(DEMO_INPUT)" >&2
	  exit 2
	fi
	if [[ -e "$(DEMO_WORKSPACE)" || -L "$(DEMO_WORKSPACE)" ]]; then
	  printf 'Refusing to reuse existing output: %s\nSet DEMO_WORKSPACE to a new path.\n' "$(DEMO_WORKSPACE)" >&2
	  exit 2
	fi

smoke: check guard-smoke
	"$(CLI)" demo --input "$(DEMO_INPUT)" --output "$(DEMO_WORKSPACE)"
	"$(CLI)" verify --workspace "$(DEMO_WORKSPACE)"

guard-download:
	if [[ -e "$(DATA24_SOURCE)" || -L "$(DATA24_SOURCE)" ]]; then
	  printf 'Refusing to write into existing dataset path: %s\n' "$(DATA24_SOURCE)" >&2
	  exit 2
	fi

dataset-download: check guard-download
	"$(PYTHON)" scripts/download_uwf_zeekdata24_parquet.py --output "$(DATA24_SOURCE)"

guard-m2:
	for path in "$(M2_AUDIT)" "$(M2_DATA)" "$(M2_BASELINE)"; do
	  if [[ -e "$$path" || -L "$$path" ]]; then
	    printf 'Refusing to reuse existing M2 output: %s\n' "$$path" >&2
	    exit 2
	  fi
	done
	if [[ ! -f "$(DATA24_SOURCE)/download_manifest.json" ]]; then
	  printf 'Expected controlled Parquet source and download manifest at %s\nRun make dataset-download first, or set DATA24_SOURCE.\n' "$(DATA24_SOURCE)" >&2
	  exit 2
	fi

m2: check guard-m2
	"$(CLI)" m2-audit --input "$(DATA24_SOURCE)" --output "$(M2_AUDIT)"
	"$(CLI)" m2-prepare --input "$(DATA24_SOURCE)" --config configs/m2-parquet.yaml --output "$(M2_DATA)"
	"$(CLI)" m2-verify --workspace "$(M2_DATA)"
	"$(CLI)" m2-train --workspace "$(M2_DATA)" --output "$(M2_BASELINE)"
	"$(CLI)" m2-verify-baseline --workspace "$(M2_BASELINE)" --dataset-workspace "$(M2_DATA)"

guard-m3:
	for path in "$(M3_IID_PARTITION)" "$(M3_NON_IID_PARTITION)" "$(M3_IID_RUN)" "$(M3_NON_IID_RUN)"; do
	  if [[ -e "$$path" || -L "$$path" ]]; then
	    printf 'Refusing to reuse existing M3 output: %s\n' "$$path" >&2
	    exit 2
	  fi
	done
	if [[ ! -f "$(M2_DATA)/manifest.json" ]]; then
	  printf 'Verified M2 dataset not found at %s\nRun make m2 first.\n' "$(M2_DATA)" >&2
	  exit 2
	fi

m3: check guard-m3
	"$(CLI)" m3-partition --dataset-workspace "$(M2_DATA)" --output "$(M3_IID_PARTITION)" --mode iid
	"$(CLI)" m3-verify-partitions --workspace "$(M3_IID_PARTITION)" --dataset-workspace "$(M2_DATA)"
	"$(CLI)" m3-partition --dataset-workspace "$(M2_DATA)" --output "$(M3_NON_IID_PARTITION)" --mode non-iid
	"$(CLI)" m3-verify-partitions --workspace "$(M3_NON_IID_PARTITION)" --dataset-workspace "$(M2_DATA)"
	"$(CLI)" m3-train --partition-workspace "$(M3_IID_PARTITION)" --dataset-workspace "$(M2_DATA)" --output "$(M3_IID_RUN)"
	"$(CLI)" m3-verify --workspace "$(M3_IID_RUN)" --partition-workspace "$(M3_IID_PARTITION)" --dataset-workspace "$(M2_DATA)"
	"$(CLI)" m3-train --partition-workspace "$(M3_NON_IID_PARTITION)" --dataset-workspace "$(M2_DATA)" --output "$(M3_NON_IID_RUN)"
	"$(CLI)" m3-verify --workspace "$(M3_NON_IID_RUN)" --partition-workspace "$(M3_NON_IID_PARTITION)" --dataset-workspace "$(M2_DATA)"

guard-foundation:
	for path in "$(M2_AUDIT)" "$(M2_DATA)" "$(M2_BASELINE)" "$(M3_IID_PARTITION)" "$(M3_NON_IID_PARTITION)" "$(M3_IID_RUN)" "$(M3_NON_IID_RUN)"; do
	  if [[ -e "$$path" || -L "$$path" ]]; then
	    printf 'Refusing to start the M2-M3 chain because an output exists: %s\n' "$$path" >&2
	    exit 2
	  fi
	done
	if [[ ! -f "$(DATA24_SOURCE)/download_manifest.json" ]]; then
	  printf 'Controlled Parquet source not found at %s\nRun make dataset-download first.\n' "$(DATA24_SOURCE)" >&2
	  exit 2
	fi

foundation: check guard-foundation
	$(MAKE) m2
	$(MAKE) m3

# Maintained navigation checks are independent of numerical campaign execution.
.PHONY: docs-check docs-index evidence-list evidence-check thesis-evidence test-docs test-formal test-groups dataset-verify

docs-check: check
	"$(PYTHON)" scripts/repository_audit.py docs

docs-index: check
	"$(PYTHON)" scripts/repository_audit.py index

evidence-list: check
	"$(PYTHON)" scripts/repository_audit.py list

evidence-check: check
	"$(PYTHON)" scripts/repository_audit.py evidence --study "$(STUDY)"

# Checks the retained evidence cited by the thesis (docs/thesis-evidence.txt).
thesis-evidence: check
	"$(PYTHON)" scripts/thesis_evidence.py

test-docs: check
	"$(PYTHON)" -m pytest -q tests/test_repository_audit.py

test-formal: check
	"$(PYTHON)" -m pytest -q tests/test_round_derivation.py tests/test_submission_evidence.py tests/test_ingestion_coverage.py tests/test_campaign_derivation.py tests/test_review_ledger.py tests/test_counterfactual_round.py tests/test_retraining_replay.py

test-groups: check
	"$(PYTHON)" -m pytest -q tests/test_retrospective_anomaly_groups.py tests/test_episodic_attribution_groups.py tests/test_selector_diagnostic_math.py tests/test_endpoint_group_allocation_guard.py

dataset-verify: check
	"$(PYTHON)" scripts/download_uwf_zeekdata24_parquet.py --output "$(DATA24_SOURCE)" --verify-only

.PHONY: test-ton-iot ton-iot-preflight

test-ton-iot: check
	"$(PYTHON)" -m pytest -q tests/test_ton_iot.py tests/test_ton_iot_preflight.py tests/test_ton_iot_collection_preflight.py tests/test_ton_iot_windows.py tests/test_ton_iot_retraining.py tests/test_ton_iot_time_bounds.py tests/test_ton_iot_calibration.py tests/test_ton_iot_margin.py tests/test_ton_iot_traffic_features.py tests/test_ton_iot_host_windows.py tests/test_ton_iot_novelty.py tests/test_ton_iot_transfer_initialization.py

ton-iot-preflight:
	if [[ ! -f "$(TON_IOT_INDEX)" ]]; then
	  printf 'Set TON_IOT_INDEX to the acquired official collection index.\n' >&2
	  exit 2
	fi
	if [[ -e "$(TON_IOT_OUTPUT)" || -L "$(TON_IOT_OUTPUT)" ]]; then
	  printf 'Refusing to reuse output: %s\nSet TON_IOT_OUTPUT to a new path.\n' "$(TON_IOT_OUTPUT)" >&2
	  exit 2
	fi
	"$(PYTHON)" scripts/revision_ton_iot_collection_preflight.py --index "$(TON_IOT_INDEX)" --pipeline-root . --output "$(TON_IOT_OUTPUT)"

.PHONY: ton-iot-windows

ton-iot-windows:
	for path in "$(TON_IOT_INDEX)" "$(TON_IOT_PREFLIGHT)" "$(TON_IOT_PROTOCOL)"; do
	  if [[ ! -f "$$path" ]]; then
	    printf 'Set TON_IOT_INDEX, TON_IOT_PREFLIGHT and TON_IOT_PROTOCOL to existing frozen inputs.\n' >&2
	    exit 2
	  fi
	done
	if [[ -e "$(TON_IOT_WINDOWS_OUTPUT)" || -L "$(TON_IOT_WINDOWS_OUTPUT)" ]]; then
	  printf 'Refusing to reuse output: %s\n' "$(TON_IOT_WINDOWS_OUTPUT)" >&2
	  exit 2
	fi
	"$(PYTHON)" scripts/prepare_ton_iot_windows.py --index "$(TON_IOT_INDEX)" --preflight "$(TON_IOT_PREFLIGHT)" --protocol "$(TON_IOT_PROTOCOL)" --output "$(TON_IOT_WINDOWS_OUTPUT)"

.PHONY: ton-iot-target-prepare ton-iot-target-train ton-iot-target-evaluate

ton-iot-target-prepare:
	if [[ ! -f "$(TON_IOT_TRANSFER)/verification.json" ]]; then
	  printf 'Set TON_IOT_TRANSFER to the verified frozen-transfer workspace.\n' >&2
	  exit 2
	fi
	if [[ -e "$(TON_IOT_TARGET_WORKSPACE)" || -L "$(TON_IOT_TARGET_WORKSPACE)" ]]; then
	  printf 'Refusing to reuse target workspace: %s\n' "$(TON_IOT_TARGET_WORKSPACE)" >&2
	  exit 2
	fi
	"$(PYTHON)" scripts/run_ton_iot_retraining.py prepare --workspace "$(TON_IOT_TARGET_WORKSPACE)" --transfer "$(TON_IOT_TRANSFER)"

ton-iot-target-train:
	if [[ ! -f "$(TON_IOT_TARGET_WORKSPACE)/protocol-before-training.json" || -e "$(TON_IOT_TARGET_WORKSPACE)/runs" ]]; then
	  printf 'A freshly prepared target workspace without existing runs is required.\n' >&2
	  exit 2
	fi
	"$(PYTHON)" scripts/run_ton_iot_retraining.py train --workspace "$(TON_IOT_TARGET_WORKSPACE)" --transfer "$(TON_IOT_TRANSFER)"

ton-iot-target-evaluate:
	if [[ ! -f "$(TON_IOT_TARGET_WORKSPACE)/training-closure-before-test.json" || -e "$(TON_IOT_TARGET_WORKSPACE)/target-test-results.json" ]]; then
	  printf 'All training selections must be closed and target evaluation must be fresh.\n' >&2
	  exit 2
	fi
	"$(PYTHON)" scripts/run_ton_iot_retraining.py evaluate --workspace "$(TON_IOT_TARGET_WORKSPACE)" --transfer "$(TON_IOT_TRANSFER)"

.PHONY: ton-iot-target-flow-select

ton-iot-target-flow-select:
	if [[ ! -f "$(TON_IOT_TARGET_WORKSPACE)/target-test-results.json" || ! -f "$(TON_IOT_TRANSFER)/verification.json" ]]; then
	  printf 'A completed target study and verified transfer workspace are required.\n' >&2
	  exit 2
	fi
	if [[ -e "$(TON_IOT_TARGET_WORKSPACE)/flow-end-selection-v2" || -L "$(TON_IOT_TARGET_WORKSPACE)/flow-end-selection-v2" ]]; then
	  printf 'Refusing to overwrite the existing temporal correction.\n' >&2
	  exit 2
	fi
	"$(PYTHON)" scripts/reselect_ton_iot_flow_end.py --workspace "$(TON_IOT_TARGET_WORKSPACE)" --transfer "$(TON_IOT_TRANSFER)"

.PHONY: ton-iot-f1-study
ton-iot-f1-study:
	if [[ -z "$(TON_IOT_F1_WORKSPACE)" || -e "$(TON_IOT_F1_WORKSPACE)" || -L "$(TON_IOT_F1_WORKSPACE)" ]]; then
	  printf 'Set TON_IOT_F1_WORKSPACE to a fresh assessment path.\n' >&2
	  exit 2
	fi
	if [[ ! -f "$(TON_IOT_TARGET_WORKSPACE)/flow-end-selection-v2/verification.json" || ! -f "$(TON_IOT_TRANSFER)/windows/occurrence-windows.json" ]]; then
	  printf 'Set verified TON_IOT_TARGET_WORKSPACE and TON_IOT_TRANSFER inputs.\n' >&2
	  exit 2
	fi
	"$(PYTHON)" scripts/run_ton_iot_f1_study.py --workspace "$(TON_IOT_F1_WORKSPACE)" --parent "$(TON_IOT_TARGET_WORKSPACE)" --transfer "$(TON_IOT_TRANSFER)"
