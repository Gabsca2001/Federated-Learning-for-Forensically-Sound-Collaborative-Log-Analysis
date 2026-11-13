.DEFAULT_GOAL := help
SHELL := /bin/bash
.SHELLFLAGS := -Eeuo pipefail -c
.ONESHELL:
.DELETE_ON_ERROR:

VENV ?= .venv
PYTHON ?= $(VENV)/bin/python
CLI ?= $(VENV)/bin/fl-forensics
STUDY ?= results/admission/revision-episodic-attribution-recovery-v1
TON_IOT_INDEX ?=
TON_IOT_OUTPUT ?= artifacts/ton-iot-preflight
TON_IOT_PREFLIGHT ?=
TON_IOT_PROTOCOL ?=
TON_IOT_WINDOWS_OUTPUT ?= artifacts/ton-iot-windows
TON_IOT_TRANSFER ?=
TON_IOT_TARGET_WORKSPACE ?= artifacts/ton-iot-target-retraining

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
	  '  make experiments       List the targets that re-run completed experiments' \
	  '' \
	  'Documentation and retained evidence:' \
	  '  make docs-check        Check maintained docs, catalogues and retained Markdown' \
	  '  make docs-index        Regenerate the two registered catalogue files' \
	  '  make evidence-list     List all retained study directories' \
	  '  make evidence-check    Check the selected stored flat checksum publication' \
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
	  '  make validate          Run package checks, tests, lint and fixture smoke' \
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
	  'DEMO_INPUT and DEMO_WORKSPACE. Generation targets refuse existing outputs.' \
	  'M4-M8 deployments remain profile-specific; see docs/README.md.'

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

validate: test lint smoke

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
.PHONY: docs-check docs-index evidence-list evidence-check test-docs test-formal test-groups dataset-verify

docs-check:
	"$(PYTHON)" scripts/repository_audit.py docs

docs-index:
	"$(PYTHON)" scripts/repository_audit.py index

evidence-list:
	"$(PYTHON)" scripts/repository_audit.py list

evidence-check:
	"$(PYTHON)" scripts/repository_audit.py evidence --study "$(STUDY)"

test-docs: check
	"$(PYTHON)" -m pytest -q tests/test_repository_audit.py

test-formal: check
	"$(PYTHON)" -m pytest -q tests/test_round_derivation.py tests/test_submission_evidence.py tests/test_ingestion_coverage.py tests/test_campaign_derivation.py tests/test_review_ledger.py tests/test_counterfactual_round.py tests/test_retraining_replay.py

test-groups: check
	"$(PYTHON)" -m pytest -q tests/test_retrospective_anomaly_groups.py tests/test_episodic_attribution_groups.py tests/test_selector_diagnostic_math.py tests/test_endpoint_group_allocation_guard.py

dataset-verify: check
	"$(PYTHON)" scripts/download_uwf_zeekdata24_parquet.py --output "$(DATA24_SOURCE)" --verify-only

.PHONY: test-ton-iot ton-iot-preflight

test-ton-iot:
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

# ---------------------------------------------------------------------------------------------
# Experiment reproduction. Each target re-runs a completed study with its own controller.
# The controllers refuse to write into an existing workspace: archive or move the old one first,
# or pass LAB= where the controller supports it. Training phases are long; WORKERS defaults
# to 2 to fit the WSL memory limit.
WORKERS ?= 2
PHASE ?=
REPORT_ARGS ?=
REPORT_DIR ?= artifacts/reports

.PHONY: experiments gate-factorial head-cusum head-v2 head-v2-confirm trigger-probe probe-evasion
.PHONY: probe-keynorm global-probe live-probe-rollback clean-gate-calibration severe-tail-gate
.PHONY: gate-trajectories gate-mechanism-audit mass-safety
.PHONY: multisource-fl multisource-confirmation two-view-confirmation unsw-generalization
.PHONY: unsw-s0-confirmation label-efficiency lofo domain-adaptation domain-adaptation-controls
.PHONY: prototype-reanchoring ton-iot-robust-transfer m6-policy-sensitivity-replay m6-adaptive-frozen-verify

PHASE_USAGE = printf 'Set PHASE to one of: %s\n' "$(1)" >&2; exit 2

experiments:
	@printf '%s\n' \
	  'Experiment reproduction targets (see docs/guide/REPRODUCIBILITY.md):' \
	  '' \
	  'Phased gate and probe studies: make <target> PHASE=<phase> [WORKERS=2] [LAB=...]' \
	  '  Order: calibrate -> prepare -> guard -> verify-guard -> guard-decide -> evaluation' \
	  '         -> verify-evaluation -> test -> report (only the phases a study has)' \
	  '  gate-factorial        Gate x aggregation factorial (negative)' \
	  '  head-cusum            Head-aware CUSUM gate (retired)' \
	  '  head-v2               head_v2 gate, exploratory study (retired)' \
	  '  head-v2-confirm       head_v2 + clipping, confirmatory (guard not passed)' \
	  '  trigger-probe         Behavioural trigger probe + clipping, live' \
	  '  probe-evasion         Probe vs probe-aware attacker' \
	  '  probe-keynorm         Per-key normalised probe, confirmatory' \
	  '  global-probe          Global-model probe with rollback, confirmatory' \
	  '  live-probe-rollback   Signed swtpm live case (Docker; LAB=fresh workspace)' \
	  '' \
	  'Single-pipeline studies:' \
	  '  clean-gate-calibration  severe-tail-gate  gate-trajectories  gate-mechanism-audit  mass-safety' \
	  '' \
	  'External-dataset studies (each refuses if its frozen protocol digest differs):' \
	  '  multisource-fl  multisource-confirmation  two-view-confirmation  unsw-generalization' \
	  '  unsw-s0-confirmation  label-efficiency  lofo  domain-adaptation  domain-adaptation-controls' \
	  '  prototype-reanchoring  ton-iot-robust-transfer PHASE=train|evaluate' \
	  '  ToN-IoT preflight, windows, target retraining and F1 assessment: see make help' \
	  '' \
	  'Milestone replays: m6-policy-sensitivity-replay  m6-adaptive-frozen-verify' \
	  '' \
	  'Inputs moved to the external SSD: make restore-artifact ARCHIVE=<name> (SHA-256 checked first)' \
	  '' \
	  'Not available as targets: the M4-M8 deployments and the admission and containment studies' \
	  'in results/admission/. Their controllers are kept in each publication folder and follow' \
	  'the procedure described in that README.'

gate-factorial: LAB ?= artifacts/revision-gate-aggregation-factorial-v1
gate-factorial: check
	case "$(PHASE)" in
	  prepare|guard|guard-decide|evaluation) "$(PYTHON)" scripts/revision_gate_aggregation_factorial.py "$(PHASE)" --lab "$(LAB)" --workers "$(WORKERS)";;
	  report) "$(PYTHON)" scripts/report_arm_study.py --lab "$(LAB)" --out "$(REPORT_DIR)/gate-factorial" $(REPORT_ARGS);;
	  *) $(call PHASE_USAGE,prepare guard guard-decide evaluation report);;
	esac

head-cusum: LAB ?= artifacts/revision-head-cusum-gate-v1
head-cusum: check
	case "$(PHASE)" in
	  prepare|fit|guard|guard-decide|evaluation) "$(PYTHON)" scripts/revision_head_cusum_study.py "$(PHASE)" --lab "$(LAB)" --workers "$(WORKERS)";;
	  verify-guard) "$(PYTHON)" scripts/revision_head_cusum_audit.py guard --lab "$(LAB)";;
	  verify-evaluation) "$(PYTHON)" scripts/revision_head_cusum_audit.py evaluation --lab "$(LAB)";;
	  test) "$(PYTHON)" scripts/revision_head_cusum_test.py --lab "$(LAB)" --workers "$(WORKERS)";;
	  report) "$(PYTHON)" scripts/report_head_cusum_study.py --lab "$(LAB)" --out "$(REPORT_DIR)/head-cusum";;
	  *) $(call PHASE_USAGE,prepare fit guard verify-guard guard-decide evaluation verify-evaluation test report);;
	esac

head-v2: LAB ?= artifacts/revision-head-gate-v2
head-v2: check
	case "$(PHASE)" in
	  prepare|fit|guard|guard-decide|evaluation) "$(PYTHON)" scripts/revision_head_v2_study.py "$(PHASE)" --lab "$(LAB)" --workers "$(WORKERS)";;
	  verify-guard) "$(PYTHON)" scripts/revision_head_v2_audit.py guard --lab "$(LAB)";;
	  verify-evaluation) "$(PYTHON)" scripts/revision_head_v2_audit.py evaluation --lab "$(LAB)";;
	  report) "$(PYTHON)" scripts/report_arm_study.py --lab "$(LAB)" --out "$(REPORT_DIR)/head-v2" $(REPORT_ARGS);;
	  *) $(call PHASE_USAGE,prepare fit guard verify-guard guard-decide evaluation verify-evaluation report);;
	esac

head-v2-confirm: LAB ?= artifacts/revision-head-gate-v2-confirm
head-v2-confirm: check
	case "$(PHASE)" in
	  prepare|guard|guard-decide|evaluation) "$(PYTHON)" scripts/revision_head_v2_confirm.py "$(PHASE)" --lab "$(LAB)" --workers "$(WORKERS)";;
	  verify-guard) "$(PYTHON)" scripts/revision_head_v2_audit.py guard --lab "$(LAB)";;
	  verify-evaluation) "$(PYTHON)" scripts/revision_head_v2_audit.py evaluation --lab "$(LAB)";;
	  test) "$(PYTHON)" scripts/revision_head_cusum_test.py --lab "$(LAB)" --workers "$(WORKERS)";;
	  report) "$(PYTHON)" scripts/report_arm_study.py --lab "$(LAB)" --out "$(REPORT_DIR)/head-v2-confirm" $(REPORT_ARGS);;
	  *) $(call PHASE_USAGE,prepare guard verify-guard guard-decide evaluation verify-evaluation test report);;
	esac

trigger-probe: LAB ?= artifacts/revision-trigger-probe-live
trigger-probe: check
	case "$(PHASE)" in
	  prepare|guard|guard-decide|evaluation) "$(PYTHON)" scripts/revision_probe_study.py "$(PHASE)" --lab "$(LAB)" --workers "$(WORKERS)";;
	  verify-guard) "$(PYTHON)" scripts/revision_probe_audit.py guard --lab "$(LAB)";;
	  verify-evaluation) "$(PYTHON)" scripts/revision_probe_audit.py evaluation --lab "$(LAB)";;
	  test) "$(PYTHON)" scripts/revision_head_cusum_test.py --lab "$(LAB)" --workers "$(WORKERS)";;
	  report) "$(PYTHON)" scripts/report_arm_study.py --lab "$(LAB)" --out "$(REPORT_DIR)/trigger-probe" $(REPORT_ARGS);;
	  *) $(call PHASE_USAGE,prepare guard verify-guard guard-decide evaluation verify-evaluation test report);;
	esac

# These three controllers use a fixed workspace: move the existing one aside before a fresh run.
probe-evasion: check
	L=artifacts/revision-trigger-probe-evasion-live
	case "$(PHASE)" in
	  calibrate|prepare|guard|guard-decide|evaluation|test) "$(PYTHON)" scripts/revision_probe_evasion_study.py "$(PHASE)" --workers "$(WORKERS)";;
	  verify-guard) "$(PYTHON)" scripts/revision_probe_evasion_audit.py guard --lab "$$L";;
	  verify-evaluation) "$(PYTHON)" scripts/revision_probe_evasion_audit.py evaluation --lab "$$L";;
	  report) "$(PYTHON)" scripts/report_arm_study.py --lab "$$L" --out "$(REPORT_DIR)/probe-evasion" $(REPORT_ARGS);;
	  *) $(call PHASE_USAGE,calibrate prepare guard verify-guard guard-decide evaluation verify-evaluation test report);;
	esac

probe-keynorm: check
	L=artifacts/revision-probe-keynorm-confirm
	case "$(PHASE)" in
	  calibrate|prepare|guard|guard-decide|evaluation|test) "$(PYTHON)" scripts/revision_probe_keynorm_study.py "$(PHASE)" --workers "$(WORKERS)";;
	  verify-guard) "$(PYTHON)" scripts/revision_probe_keynorm_audit.py guard --lab "$$L";;
	  verify-evaluation) "$(PYTHON)" scripts/revision_probe_keynorm_audit.py evaluation --lab "$$L";;
	  report) "$(PYTHON)" scripts/report_arm_study.py --lab "$$L" --out "$(REPORT_DIR)/probe-keynorm" $(REPORT_ARGS);;
	  *) $(call PHASE_USAGE,calibrate prepare guard verify-guard guard-decide evaluation verify-evaluation test report);;
	esac

global-probe: check
	L=artifacts/revision-global-probe-confirm
	case "$(PHASE)" in
	  calibrate|prepare|guard|guard-decide|evaluation|test) "$(PYTHON)" scripts/revision_global_probe_study.py "$(PHASE)" --workers "$(WORKERS)";;
	  verify-guard) "$(PYTHON)" scripts/revision_global_probe_audit.py guard --lab "$$L";;
	  verify-evaluation) "$(PYTHON)" scripts/revision_global_probe_audit.py evaluation --lab "$$L";;
	  report) "$(PYTHON)" scripts/report_arm_study.py --lab "$$L" --out "$(REPORT_DIR)/global-probe" $(REPORT_ARGS);;
	  *) $(call PHASE_USAGE,calibrate prepare guard verify-guard guard-decide evaluation verify-evaluation test report);;
	esac

live-probe-rollback: check
	if [[ -z "$(LAB)" || -e "$(LAB)" ]]; then
	  printf 'Set LAB to a fresh workspace under artifacts/ (Docker and the probe-rollback image are required).\n' >&2
	  exit 2
	fi
	"$(PYTHON)" scripts/revision_live_probe_rollback.py --stage prepare --workspace "$(LAB)" --variant "$${VARIANT:-bounded}"
	"$(PYTHON)" scripts/revision_live_probe_rollback.py --workspace "$(LAB)" --variant "$${VARIANT:-bounded}"

clean-gate-calibration: check
	"$(PYTHON)" scripts/revision_clean_gate_study.py pipeline --workers "$(WORKERS)"
	"$(PYTHON)" scripts/revision_clean_gate_audit.py evaluation --workers "$(WORKERS)"
	"$(PYTHON)" scripts/report_clean_gate_study.py

severe-tail-gate: check
	"$(PYTHON)" scripts/revision_severe_gate_study.py pipeline --workers "$(WORKERS)"
	"$(PYTHON)" scripts/check_severe_models.py
	"$(PYTHON)" scripts/report_severe_gate.py
	"$(PYTHON)" scripts/check_severe_publication.py

gate-trajectories: check
	"$(PYTHON)" scripts/revision_gate_trajectories.py prepare
	"$(PYTHON)" scripts/revision_gate_trajectories.py run --workers "$(WORKERS)"
	"$(PYTHON)" scripts/revision_gate_trajectories_audit.py --workers "$(WORKERS)"
	"$(PYTHON)" scripts/report_gate_trajectories.py

gate-mechanism-audit: check
	"$(PYTHON)" scripts/revision_gate_mechanism_audit.py --verify

mass-safety: check
	"$(PYTHON)" scripts/revision_mass_safety_audit.py
	"$(PYTHON)" scripts/finalize_mass_safety.py

multisource-fl: check
	"$(PYTHON)" scripts/multisource_fl.py
multisource-confirmation: check
	"$(PYTHON)" scripts/multisource_data24_confirmation.py
two-view-confirmation: check
	"$(PYTHON)" scripts/two_view_confirmation.py
unsw-generalization: check
	"$(PYTHON)" scripts/unsw_generalization.py
unsw-s0-confirmation: check
	"$(PYTHON)" scripts/unsw_s0_confirmation.py
label-efficiency: check
	"$(PYTHON)" scripts/label_efficiency.py
lofo: check
	"$(PYTHON)" scripts/label_efficiency_lofo.py
domain-adaptation: check
	"$(PYTHON)" scripts/domain_adaptation_eval.py
domain-adaptation-controls: check
	"$(PYTHON)" scripts/domain_adaptation_controls.py
prototype-reanchoring: check
	"$(PYTHON)" scripts/prototype_reanchoring.py

ton-iot-robust-transfer: check
	case "$(PHASE)" in
	  train|evaluate) "$(PYTHON)" scripts/ton_iot_robust_transfer.py "$(PHASE)";;
	  *) $(call PHASE_USAGE,train evaluate);;
	esac

m6-policy-sensitivity-replay: check
	"$(PYTHON)" scripts/replay_m6_policy_sensitivity.py --verify

m6-adaptive-frozen-verify: check
	"$(PYTHON)" scripts/run_m6_adaptive_frozen.py verify

# Restore an offloaded artifact from the external SSD after checking its SHA-256 against the manifest.
ARCHIVE_DIR ?= /mnt/d/fl-artifacts-archive
OFFLOAD_MANIFEST ?= results/records/artifact-offload/manifest.jsonl
.PHONY: restore-artifact
restore-artifact:
	if [[ -z "$(ARCHIVE)" ]]; then
	  printf 'Set ARCHIVE to an archive name listed in %s\n' "$(OFFLOAD_MANIFEST)" >&2
	  exit 2
	fi
	file="$(ARCHIVE_DIR)/$(ARCHIVE).tar.gz"
	if [[ ! -f "$$file" ]]; then
	  printf 'Archive not found: %s (is D: mounted? see docs/records/ARTIFACT_OFFLOAD.md)\n' "$$file" >&2
	  exit 2
	fi
	expected=$$("$(PYTHON)" -c 'import json,sys; rows=[json.loads(l) for l in open(sys.argv[1])]; print(next((r.get("archive_sha256") or r.get("sha256", "") for r in reversed(rows) if r["archive"].endswith("/"+sys.argv[2]+".tar.gz")), ""))' "$(OFFLOAD_MANIFEST)" "$(ARCHIVE)")
	if [[ -z "$$expected" ]]; then
	  printf 'No manifest entry for %s\n' "$(ARCHIVE)" >&2
	  exit 2
	fi
	actual=$$(sha256sum "$$file" | cut -d' ' -f1)
	if [[ "$$actual" != "$$expected" ]]; then
	  printf 'SHA-256 mismatch for %s\n' "$$file" >&2
	  exit 1
	fi
	tar -I pigz -xkf "$$file" -C artifacts
	printf 'Restored %s into artifacts/ (existing files were kept).\n' "$(ARCHIVE)"
