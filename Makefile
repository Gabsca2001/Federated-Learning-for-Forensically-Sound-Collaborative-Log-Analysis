.DEFAULT_GOAL := help
SHELL := /bin/bash
.SHELLFLAGS := -Eeuo pipefail -c
.ONESHELL:
.DELETE_ON_ERROR:

VENV ?= .venv
PYTHON ?= $(VENV)/bin/python
CLI ?= $(VENV)/bin/fl-forensics

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
	  'Minimal reproducibility entry points:' \
	  '  make setup              Create .venv and install project extras' \
	  '  make check              Check installed Python package and CLI' \
	  '  make doctor             Also check Docker Compose and OpenSSL' \
	  '  make test               Run pytest' \
	  '  make lint               Run the documented Ruff error checks' \
	  '  make smoke              Run and verify the M1 fixture demo' \
	  '  make validate           Run tests, lint, and the M1 smoke demo' \
	  '  make dataset-download  Download the documented Data24 Parquet source' \
	  '  make m2                 Build and verify the canonical M2 artifacts' \
	  '  make m3                 Build and verify IID/non-IID M3 baselines' \
	  '  make foundation         Run M2 then M3 (requires source data already present)' \
	  '' \
	  'Targets refuse to reuse existing output paths. Override path variables for a fresh run.'

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
	"$(PYTHON)" -m ruff check --select E9,F63,F7,F82 src tests

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
	"$(PYTHON)" scripts/download_uwf_zeekdata24_parquet.py

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
