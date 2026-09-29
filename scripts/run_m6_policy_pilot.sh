#!/usr/bin/env bash
# Fresh-only paired pilot using the existing M4/M5 generators and verifiers.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
phase="${1:-smoke}"
case "$phase" in
  smoke) rounds=1 ;;
  pilot) rounds=30 ;;
  *) echo "Usage: bash scripts/run_m6_policy_pilot.sh [smoke|pilot]" >&2; exit 2 ;;
esac
export PATH="$PWD/.venv/bin:$PATH"
partition=artifacts/m3-data24-parquet-iid-local-test-v1
fl-forensics m3-verify-partitions --workspace "$partition" --dataset-workspace artifacts/m2-data24-parquet
# The pilot is seed 341593, CPU, with fixed calibration and identical assignments.
python - <<'PY'
import hashlib
import json
import yaml
from pathlib import Path
config = yaml.safe_load(Path("configs/federation.yaml").read_text())
assert config["training"]["seed"] == config["partitioning"]["seed"] == 341593
assert config["training"]["device"] == "cpu"
partition = json.loads(Path("artifacts/m3-data24-parquet-iid-local-test-v1/manifest.json").read_text())
assert partition["seed"] == 341593 and partition["partition_mode"] == "iid"
assert partition["partition_config_sha256"] == hashlib.sha256(Path("configs/federation.yaml").read_bytes()).hexdigest()
gated = yaml.safe_load(Path("configs/in-round-admission.yaml").read_text())["runtime_admission"]
sequential = yaml.safe_load(Path("configs/in-round-admission-sequential.yaml").read_text())["runtime_admission"]
assert gated["primary_policy"] == "gated_composite"
assert sequential["primary_policy"] == "sequential"
for settings in (gated, sequential):
    settings.pop("primary_policy")
    settings.pop("policy_id")
assert gated == sequential, "paired policies must share fixed calibration"
PY
if [[ "$phase" == pilot ]]; then
  test -f artifacts/m6-policy-smoke-v1-complete.txt || { echo "Complete the smoke phase first" >&2; exit 1; }
fi
# Preflight every destination before provisioning anything.
for policy in gated_composite sequential; do
  for condition in clean disagreement; do
    tag="m6-policy-${phase}-${policy}-${condition}-s341593-v1"
    for target in "artifacts/$tag" "artifacts/$tag-trust" "artifacts/$tag-nodes"; do
      if [[ -e "$target" ]]; then
        echo "Existing workspace: $target. Preserve and investigate before retrying." >&2
        exit 1
      fi
    done
    namespace="flforensics_${tag//-/_}"
    if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$namespace")" || -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$namespace")" ]]; then
      echo "Existing Docker namespace: $namespace" >&2
      exit 1
    fi
  done
done
log_file=$(mktemp "./m6-policy-${phase}-XXXXXX.log")
echo "Log: $log_file"
exec > >(tee -a "$log_file") 2>&1
for policy in gated_composite sequential; do
  for condition in clean disagreement; do
    tag="m6-policy-${phase}-${policy}-${condition}-s341593-v1"
    export COMPOSE_PROJECT_NAME="flforensics_${tag//-/_}"
    export M4_TRUST_WORKSPACE="$PWD/artifacts/$tag-trust"
    export M4_NODE_ROOT="$PWD/artifacts/$tag-nodes"
    export M5_RUNTIME_IMAGE="flforensics-m6-policy-pilot-v1:latest"
    config=configs/in-round-admission.yaml
    if [[ "$policy" == sequential ]]; then config=configs/in-round-admission-sequential.yaml; fi
    fl-forensics m4-init --workspace "$M4_TRUST_WORKSPACE" --project-root .
    python scripts/run_m4_swtpm.py provision --trust-workspace "$M4_TRUST_WORKSPACE" --node-root "$M4_NODE_ROOT"
    fl-forensics m4-enroll --workspace "$M4_TRUST_WORKSPACE" --node-root "$M4_NODE_ROOT"
    fl-forensics m4-mtls-test --workspace "$M4_TRUST_WORKSPACE" --node-root "$M4_NODE_ROOT"
    docker compose -f compose.m4.yaml --profile verify build verifier
    args=(--partition-workspace "$partition" --workspace "artifacts/$tag"
      --trust-workspace "$M4_TRUST_WORKSPACE" --node-root "$M4_NODE_ROOT"
      --in-round-admission-config "$config" --rounds "$rounds" --workers 4
      --attestation-refresh-interval 3)
    if [[ "$condition" == disagreement ]]; then
      args+=(--disagreement-experiment-config configs/trust-statistical-disagreement.yaml)
    fi
    python scripts/run_m5_secure_multiround.py run "${args[@]}"
    python scripts/run_m5_secure_multiround.py verify "${args[@]}"
    echo "VERIFIED: $tag"
    # Stop only these new TPM containers, retaining their volumes and evidence.
    tpms=()
    for i in {1..15}; do printf -v service 'tpm%02d' "$i"; tpms+=("$service"); done
    docker compose -f compose.m4.yaml stop "${tpms[@]}"
  done
done
(set -o noclobber; printf '%s\n' "All four $phase campaigns verified; log=$log_file" > "artifacts/m6-policy-${phase}-v1-complete.txt")
echo "Completed all four $phase campaigns."
