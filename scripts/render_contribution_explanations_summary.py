#!/usr/bin/env python3
"""Publish a sanitized snapshot of verified contribution explanations."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _csv_bytes(fieldnames: list[str], rows: list[dict[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != content:
            raise RuntimeError(f"refusing to overwrite different published bytes: {path}")
        return
    path.write_bytes(content)


def _profile_clients(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["client_id"]): item for item in profile["clients"]}


def _format_ids(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values) if values else "none"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    explanation_path = arguments.workspace / "explanations.json"
    traces_path = arguments.workspace / "aggregation-traces.json"
    manifest_path = arguments.workspace / "manifest.json"
    explanations = json.loads(explanation_path.read_text(encoding="utf-8"))
    traces = json.loads(traces_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    core = manifest["core"]
    if core["explanations_sha256"] != _sha256(explanation_path):
        raise ValueError("explanation payload digest differs from its manifest")
    if core["aggregation_traces_sha256"] != _sha256(traces_path):
        raise ValueError("aggregation trace digest differs from its manifest")
    records = explanations["explanations"]
    profiles = {str(item["profile_id"]): item for item in traces["profiles"]}
    expected_profiles = {
        "l2_clipping",
        "fedavg",
        "coordinate_median",
        "trimmed_mean",
        "multikrum",
        "bulyan",
    }
    if set(profiles) != expected_profiles:
        raise ValueError("published aggregation profile set is incomplete")

    status_counts = Counter(str(item["primary_status"]) for item in records)
    clipping = _profile_clients(profiles["l2_clipping"])
    trimmed = _profile_clients(profiles["trimmed_mean"])
    multikrum = _profile_clients(profiles["multikrum"])
    bulyan = _profile_clients(profiles["bulyan"])
    clipped_ids = sorted(
        client_id
        for client_id, item in clipping.items()
        if float(item["clip_scale"]) < 1.0
    )
    multikrum_excluded = sorted(
        client_id
        for client_id, item in multikrum.items()
        if item["selected"] is False
    )
    bulyan_excluded = sorted(
        client_id
        for client_id, item in bulyan.items()
        if item["bulyan_candidate_selected"] is False
    )
    fully_trimmed = sorted(
        client_id
        for client_id, item in trimmed.items()
        if int(item["retained_coordinate_count"]) == 0
    )

    summary = {
        "schema_version": "1.0",
        "explanation_bundle_id": manifest["explanation_bundle_id"],
        "campaign_id": core["source"]["campaign_id"],
        "round_number": core["source"]["round_number"],
        "candidate_attack": core["source"]["candidate_attack"],
        "explanation_count": len(records),
        "aggregation_profile_count": len(profiles),
        "primary_policy_status_counts": dict(sorted(status_counts.items())),
        "clipped_client_ids": clipped_ids,
        "fully_trimmed_client_ids": fully_trimmed,
        "multikrum_excluded_client_ids": multikrum_excluded,
        "bulyan_candidate_excluded_client_ids": bulyan_excluded,
        "attack_labels_used_for_explanations": core["gate"][
            "attack_labels_used_for_explanations"
        ],
        "interpretation_boundary": manifest["interpretation_boundary"],
        "source_admission_sha256": core["source"]["admission_sha256"],
        "source_manifest_sha256": _sha256(manifest_path),
    }
    _write_once(arguments.output / "summary.json", _json_bytes(summary))

    client_rows: list[dict[str, Any]] = []
    for record in records:
        indicator = record["ranked_statistical_components"][0]
        tensor = record["top_tensor_drivers"][0]
        client_rows.append(
            {
                "client_id": record["client_id"],
                "primary_status": record["primary_status"],
                "trust_admissible": str(record["trust"]["admissible"]).lower(),
                "statistical_risk": f"{float(record['statistical_risk']):.9f}",
                "signed_quarantine_margin": (
                    f"{float(record['statistical_signed_margin_to_quarantine']):.9f}"
                ),
                "dominant_indicator": indicator["name"],
                "indicator_weighted_contribution": (
                    f"{float(indicator['weighted_contribution']):.9f}"
                ),
                "dominant_tensor": tensor["tensor_name"],
                "tensor_squared_distance_fraction": (
                    f"{float(tensor['squared_median_distance_fraction']):.9f}"
                ),
            }
        )
    client_fields = [
        "client_id",
        "primary_status",
        "trust_admissible",
        "statistical_risk",
        "signed_quarantine_margin",
        "dominant_indicator",
        "indicator_weighted_contribution",
        "dominant_tensor",
        "tensor_squared_distance_fraction",
    ]
    _write_once(
        arguments.output / "client-explanations.csv",
        _csv_bytes(client_fields, client_rows),
    )

    treatment_rows: list[dict[str, Any]] = []
    for client_id in sorted(clipping):
        treatment_rows.append(
            {
                "client_id": client_id,
                "clip_scale": f"{float(clipping[client_id]['clip_scale']):.9f}",
                "trimmed_retained_fraction": (
                    f"{float(trimmed[client_id]['retained_coordinate_fraction']):.9f}"
                ),
                "multikrum_rank": multikrum[client_id]["krum_rank"],
                "multikrum_selected": str(multikrum[client_id]["selected"]).lower(),
                "bulyan_candidate_selected": str(
                    bulyan[client_id]["bulyan_candidate_selected"]
                ).lower(),
                "bulyan_retained_fraction": (
                    f"{float(bulyan[client_id]['retained_coordinate_fraction']):.9f}"
                ),
            }
        )
    treatment_fields = [
        "client_id",
        "clip_scale",
        "trimmed_retained_fraction",
        "multikrum_rank",
        "multikrum_selected",
        "bulyan_candidate_selected",
        "bulyan_retained_fraction",
    ]
    _write_once(
        arguments.output / "aggregator-treatment.csv",
        _csv_bytes(treatment_fields, treatment_rows),
    )

    readme = f"""# Verified forensic explanations of M6 contribution decisions

This sanitized snapshot explains how the verified joint-admission pilot and five aggregation
strategies treated the same 15 frozen round-11 contributions. It explains update-policy
decisions; it is separate from M7, which explains intrusion predictions over log features.

## Joint-admission explanations

The primary hard-gated composite policy produced:

- accepted: `{status_counts.get('accepted', 0)}`;
- accepted with reduced weight: `{status_counts.get('accepted_downweighted', 0)}`;
- statistically quarantined: `{status_counts.get('statistically_quarantined', 0)}`;
- trust quarantined: `{status_counts.get('trust_quarantined', 0)}`.

Each row in `client-explanations.csv` records the signed distance from the statistical
quarantine threshold, the largest indicator contribution, and the named parameter tensor
responsible for the largest share of squared distance from the population median. Negative
margin means the candidate is beyond the quarantine boundary. Attack labels were not used to
rank indicators, tensors, or clients.

## Robust-aggregation traces

- L2 clipping changed: {_format_ids(clipped_ids)};
- trimmed mean removed every coordinate from: {_format_ids(fully_trimmed)};
- MultiKrum did not select: {_format_ids(multikrum_excluded)};
- Bulyan candidate selection excluded: {_format_ids(bulyan_excluded)}.

These outcomes have different meanings. Clipping rescales a whole update. MultiKrum makes a
client-level selection. Trimmed mean filters independently per coordinate, so most clients can
be partially retained. Bulyan first selects candidates by Krum rank and then makes a separate
coordinate-level choice. Coordinate median has no client-level accepted/rejected set.

`aggregator-treatment.csv` publishes the exact clip scales, retained-coordinate fractions,
Krum ranks, and selection flags. Every trace was checked against the same aggregation
implementation used by M6 and independently recomputed by the bundle verifier.

## Provenance and interpretation boundary

- explanation bundle: `{manifest['explanation_bundle_id']}`;
- manifest SHA-256: `{_sha256(manifest_path)}`;
- source admission SHA-256: `{core['source']['admission_sha256']}`;
- campaign: `{core['source']['campaign_id']}`, round `{core['source']['round_number']}`;
- source attack scenario: `{core['source']['candidate_attack']}`;
- explanation count: `{len(records)}`;
- aggregation traces: `{len(profiles)}`;
- attack labels used for explanation: `false`.

These are deterministic mechanism explanations, not proof of malicious intent and not primary
Zeek evidence. The attacked update bytes retain the controlled M6 derivation limitation of the
source admission pilot. The result covers one round and one attack configuration.

`summary.json` contains the compact result and source bindings. `manifest.json` binds every
published file. Model updates, checkpoints, full tensor values, attestation payloads, TPM state,
private keys, and source data remain outside Git.
"""
    _write_once(arguments.output / "README.md", readme.encode("utf-8"))

    published = [
        "README.md",
        "aggregator-treatment.csv",
        "client-explanations.csv",
        "summary.json",
    ]
    public_manifest = {
        "schema_version": "1.0",
        "artifact_type": "published_contribution_explanation_snapshot",
        "source_manifest_sha256": _sha256(manifest_path),
        "files": {
            name: {"sha256": _sha256(arguments.output / name)} for name in published
        },
    }
    _write_once(arguments.output / "manifest.json", _json_bytes(public_manifest))
    print(
        json.dumps(
            {
                "status": "published",
                "file_count": len(published) + 1,
                "source_manifest_sha256": _sha256(manifest_path),
                "workspace": str(arguments.output),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
