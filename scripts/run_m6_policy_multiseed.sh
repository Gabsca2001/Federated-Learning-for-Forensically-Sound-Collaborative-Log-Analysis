#!/usr/bin/env bash
# Fresh-only paired pilot using the existing M4/M5 generators and verifiers.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
phase=multiseed
rounds=30
seeds=(342593 343593 344593 345593)
export PATH="$PWD/.venv/bin:$PATH"
# Validate immutable pilot inputs and every planned configuration before Docker work.
python scripts/check_m6_policy_multiseed.py
# Preflight every destination before provisioning anything.
for seed in "${seeds[@]}"; do
for policy in gated_composite sequential; do
  for condition in clean disagreement; do
    tag="m6-policy-${phase}-${policy}-${condition}-s${seed}-v1"
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
done
log_file=$(mktemp "./m6-policy-${phase}-XXXXXX.log")
echo "Log: $log_file"
exec > >(tee -a "$log_file") 2>&1
for seed in "${seeds[@]}"; do
partition="artifacts/m6-policy-partition-s${seed}-v1"
federation="configs/federation-m6-policy-seed-${seed}.yaml"
if [[ ! -e "$partition" ]]; then
  fl-forensics m3-partition --dataset-workspace artifacts/m2-data24-parquet --config "$federation" --mode iid --output "$partition"
fi
fl-forensics m3-verify-partitions --workspace "$partition" --dataset-workspace artifacts/m2-data24-parquet
for policy in gated_composite sequential; do
  for condition in clean disagreement; do
    tag="m6-policy-${phase}-${policy}-${condition}-s${seed}-v1"
    export COMPOSE_PROJECT_NAME="flforensics_${tag//-/_}"
    export M4_TRUST_WORKSPACE="$PWD/artifacts/$tag-trust"
    export M4_NODE_ROOT="$PWD/artifacts/$tag-nodes"
    export M5_RUNTIME_IMAGE="flforensics-m6-policy-multiseed-v1:latest"
    config=configs/in-round-admission.yaml
    if [[ "$policy" == sequential ]]; then config=configs/in-round-admission-sequential.yaml; fi
    fl-forensics m4-init --workspace "$M4_TRUST_WORKSPACE" --project-root .
    python scripts/run_m4_swtpm.py provision --trust-workspace "$M4_TRUST_WORKSPACE" --node-root "$M4_NODE_ROOT"
    fl-forensics m4-enroll --workspace "$M4_TRUST_WORKSPACE" --node-root "$M4_NODE_ROOT"
    fl-forensics m4-mtls-test --workspace "$M4_TRUST_WORKSPACE" --node-root "$M4_NODE_ROOT"
    docker compose -f compose.m4.yaml --profile verify build verifier
    args=(--federation-config "$federation" --partition-workspace "$partition" --workspace "artifacts/$tag"
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
done
(set -o noclobber; printf '%s\n' "All sixteen $phase campaigns verified; log=$log_file" > "artifacts/m6-policy-${phase}-v1-complete.txt")
echo "Completed all sixteen $phase campaigns."
