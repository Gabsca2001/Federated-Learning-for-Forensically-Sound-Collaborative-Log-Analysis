#!/usr/bin/env python3
"""Publish a small sanitized snapshot of a verified joint-admission artifact."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

POLICIES = ("tpm_only", "statistics_only", "sequential", "gated_composite")


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != content:
            raise RuntimeError(f"refusing to overwrite different published bytes: {path}")
        return
    path.write_bytes(content)


def _decision_statuses(record: dict[str, Any]) -> dict[str, str]:
    statuses = {str(item["policy"]): str(item["status"]) for item in record["decisions"]}
    if set(statuses) != set(POLICIES):
        raise ValueError("record does not contain exactly the four admission policies")
    return statuses


def _csv_bytes(fieldnames: list[str], rows: list[dict[str, Any]]) -> bytes:
    import io

    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def _policy_table(evaluations: dict[str, dict[str, int]]) -> str:
    labels = {
        "tpm_only": "TPM only",
        "statistics_only": "Statistics only",
        "sequential": "Sequential",
        "gated_composite": "Gated composite",
    }
    lines = ["| Policy | TP | FP | TN | FN |", "| --- | ---: | ---: | ---: | ---: |"]
    for policy in POLICIES:
        item = evaluations[policy]
        lines.append(
            f"| {labels[policy]} | {item['true_positive']} | {item['false_positive']} | "
            f"{item['true_negative']} | {item['false_negative']} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    source_path = arguments.workspace / "admission.json"
    artifact = json.loads(source_path.read_text(encoding="utf-8"))
    if artifact.get("artifact_type") != "m6_joint_trust_statistical_admission":
        raise ValueError("unsupported joint-admission artifact")
    source_sha256 = _sha256(source_path)

    summary = {
        "schema_version": "1.0",
        "experiment_id": artifact["experiment_id"],
        "campaign_id": artifact["campaign_id"],
        "round_number": artifact["round_number"],
        "candidate_attack": artifact["candidate_attack"],
        "client_count": len(artifact["clients"]),
        "attacker_count": len(artifact["attacker_ids"]),
        "evaluation_labels_used_for_scoring": artifact[
            "evaluation_labels_used_for_scoring"
        ],
        "thresholds": artifact["thresholds"],
        "observed_quadrant_counts": artifact["quadrant_counts"],
        "observed_policy_evaluation": artifact["policy_evaluation"],
        "controlled_matrix_selection": artifact["controlled_matrix_selection"],
        "controlled_policy_evaluation": artifact["controlled_policy_evaluation"],
        "candidate_binding_semantics": artifact["candidate_binding_semantics"],
        "source_admission_sha256": source_sha256,
    }
    _write_once(arguments.output / "summary.json", _json_bytes(summary))

    client_rows: list[dict[str, Any]] = []
    for record in artifact["clients"]:
        statuses = _decision_statuses(record)
        client_rows.append(
            {
                "client_id": record["client_id"],
                "evaluation_label": record["evaluation_label"],
                "candidate_update_binding": record["candidate_update_binding"],
                "trust_admissible": str(record["trust"]["admissible"]).lower(),
                "statistical_risk": f"{float(record['statistics']['risk']):.9f}",
                **{policy: statuses[policy] for policy in POLICIES},
            }
        )
    client_fields = [
        "client_id",
        "evaluation_label",
        "candidate_update_binding",
        "trust_admissible",
        "statistical_risk",
        *POLICIES,
    ]
    _write_once(
        arguments.output / "clients.csv", _csv_bytes(client_fields, client_rows)
    )

    matrix_rows: list[dict[str, Any]] = []
    for case in artifact["controlled_disagreement_cases"]:
        statuses = _decision_statuses(case)
        matrix_rows.append(
            {
                "condition": case["condition"],
                "source_client_id": case["source_client_id"],
                "trust_intervention": case["trust_intervention"],
                "security_label": case["security_label"],
                "statistical_risk": f"{float(case['statistics']['risk']):.9f}",
                **{policy: statuses[policy] for policy in POLICIES},
            }
        )
    matrix_fields = [
        "condition",
        "source_client_id",
        "trust_intervention",
        "security_label",
        "statistical_risk",
        *POLICIES,
    ]
    _write_once(
        arguments.output / "controlled-disagreement.csv",
        _csv_bytes(matrix_fields, matrix_rows),
    )

    thresholds = artifact["thresholds"]
    readme = f"""# Verified joint TPM/statistical admission pilot

This sanitized snapshot compares four contribution-admission policies over the same verified
round-11 M4/M5 identities and M6 model-replacement population. Scores and thresholds were
calculated without candidate attack labels; labels were used only for the evaluation below.

## Observed candidate population

The candidate set contains {len(artifact['clients'])} clients, including
{len(artifact['attacker_ids'])} controlled anomalous updates. All observed M4/M5 trust signals
passed, so this population measures the `trust-valid / statistically-anomalous` disagreement.
The clean-calibrated statistical threshold is
`{float(thresholds['statistical_threshold']):.6f}` and the gated-composite quarantine threshold
is `{float(thresholds['composite_threshold']):.6f}`.

{_policy_table(artifact['policy_evaluation'])}

TPM-only accepts all three controlled anomalous updates. The other three policies quarantine
them with no benign quarantine in this fixed pilot. Gated-composite also marks one benign
candidate as `accepted_downweighted`; it still contributes and is therefore not counted as a
positive/quarantine in the table.

## Controlled disagreement matrix

The 2x2 matrix reuses one verified normal update and one verified attacked update. Each is
evaluated once with its observed passed trust signal and once with an explicit counterfactual
`fresh_attestation` failure. Counterfactual cells are policy-evaluation controls and were never
admitted by M5.

{_policy_table(artifact['controlled_policy_evaluation'])}

TPM-only misses the trust-valid anomalous update; statistics-only misses the trust-invalid
normal-looking update. Sequential and hard-gated composite catch all three unsafe cells and
retain the single safe cell in this controlled matrix.

## Provenance and limitations

- source `admission.json` SHA-256: `{source_sha256}`;
- source campaign: `{artifact['campaign_id']}`, round `{artifact['round_number']}`;
- attack: `{artifact['candidate_attack']}`;
- evaluation labels used for scoring: `{str(artifact['evaluation_labels_used_for_scoring']).lower()}`;
- the full source artifact was independently recomputed with
  `m6-verify-joint-admission` before publication;
- attacked candidate bytes are controlled M6 derivations, not newly signed M5 submissions;
- failed-trust cells are declared counterfactual controls, not observed admissions;
- this single round/attack is a mechanism demonstration, not a population-level estimate.

`summary.json` contains the compact policy results and source binding. `clients.csv` exposes
only generic client IDs, risk values, binding semantics, and decisions.
`controlled-disagreement.csv` contains the four policy-control cells. Private keys, TPM state,
attestation payloads, model updates, checkpoints, and source data remain outside Git.
"""
    _write_once(arguments.output / "README.md", readme.encode("utf-8"))

    published = [
        "README.md",
        "clients.csv",
        "controlled-disagreement.csv",
        "summary.json",
    ]
    manifest = {
        "schema_version": "1.0",
        "artifact_type": "published_composite_admission_snapshot",
        "source_admission_sha256": source_sha256,
        "files": {
            name: {"sha256": _sha256(arguments.output / name)} for name in published
        },
    }
    _write_once(arguments.output / "manifest.json", _json_bytes(manifest))
    print(
        json.dumps(
            {
                "status": "published",
                "source_admission_sha256": source_sha256,
                "file_count": len(published) + 1,
                "workspace": str(arguments.output),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
