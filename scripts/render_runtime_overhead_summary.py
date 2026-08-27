#!/usr/bin/env python3
"""Publish a compact, sanitized view of a verified runtime-overhead receipt."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt

from fl_forensics.canonical import canonical_json_bytes, digest_object, sha256_file
from fl_forensics.runtime_overhead import (
    RUNTIME_STAGE_IDS,
    verify_runtime_overhead_receipt,
)

plt.switch_backend("Agg")


STAGE_LABELS = {
    "m4-trust-initialization": "M4 trust initialization",
    "m4-swtpm-provisioning-15-clients": "M4 15-client swtpm provisioning",
    "m4-enrollment-15-clients": "M4 15-client enrollment",
    "m4-mtls-15-handshakes": "M4 15 mTLS handshakes",
    "m4-swtpm-esk-sign-probe": "M4 swtpm ESK probe (external)",
    "m4-challenge-issuance-15-clients": "M4 15 challenge issuance",
    "m4-swtpm-quote-generation-15-clients": "M4 15 TPM Quote generation",
    "m4-quote-appraisal-15-clients": "M4 15 Quote appraisal",
    "m5-round-context-initialization": "M5 round-context initialization",
    "m5-client-train-validate-sign-15-clients": "M5 15-client train/validate/sign",
    "m5-admission-fedavg": "M5 admission and FedAvg",
    "m5-independent-round-verification": "M5 independent round verification",
}

SPAN_LABELS = {
    "bootstrap": "Bootstrap",
    "trust-gate": "Trust-related group\n(includes ESK probe)",
    "secure-round": "Secure round",
    "measured-total": "All measured stages",
}


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("artifact_type") != "runtime_overhead_summary":
        raise ValueError("not a runtime-overhead summary")
    if [item.get("stage_id") for item in value.get("stages", [])] != list(
        RUNTIME_STAGE_IDS
    ):
        raise ValueError("runtime-overhead stage set or ordering mismatch")
    if [item.get("span_id") for item in value.get("spans", [])] != list(
        SPAN_LABELS
    ):
        raise ValueError("runtime-overhead span set or ordering mismatch")
    return value


def _milliseconds(value: float) -> float:
    return float(value) / 1_000_000.0


def _seconds_from_stage(stage: dict[str, Any]) -> float:
    return float(stage["median_wall_time_ms"]) / 1000.0


def _write_stage_csv(summary: dict[str, Any], path: Path) -> None:
    columns = (
        "stage_id",
        "trial_count",
        "median_wall_time_ms",
        "mean_wall_time_ms",
        "minimum_wall_time_ms",
        "maximum_wall_time_ms",
        "population_standard_deviation_ms",
        "internal_sign_median_ms_across_trials",
        "internal_sign_sample_count",
    )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for stage in summary["stages"]:
            wall = stage["wall_time_ns"]
            writer.writerow(
                {
                    "stage_id": stage["stage_id"],
                    "trial_count": wall["count"],
                    "median_wall_time_ms": stage["median_wall_time_ms"],
                    "mean_wall_time_ms": _milliseconds(wall["mean_ns"]),
                    "minimum_wall_time_ms": _milliseconds(wall["minimum_ns"]),
                    "maximum_wall_time_ms": _milliseconds(wall["maximum_ns"]),
                    "population_standard_deviation_ms": _milliseconds(
                        wall["population_std_ns"]
                    ),
                    "internal_sign_median_ms_across_trials": stage.get(
                        "internal_sign_median_ms_across_trials", ""
                    ),
                    "internal_sign_sample_count": stage.get(
                        "internal_sign_sample_count", ""
                    ),
                }
            )


def _write_span_csv(summary: dict[str, Any], path: Path) -> None:
    columns = (
        "span_id",
        "trial_count",
        "median_wall_time_ms",
        "mean_wall_time_ms",
        "minimum_wall_time_ms",
        "maximum_wall_time_ms",
        "population_standard_deviation_ms",
    )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for span in summary["spans"]:
            wall = span["wall_time_ns"]
            writer.writerow(
                {
                    "span_id": span["span_id"],
                    "trial_count": wall["count"],
                    "median_wall_time_ms": span["median_wall_time_ms"],
                    "mean_wall_time_ms": _milliseconds(wall["mean_ns"]),
                    "minimum_wall_time_ms": _milliseconds(wall["minimum_ns"]),
                    "maximum_wall_time_ms": _milliseconds(wall["maximum_ns"]),
                    "population_standard_deviation_ms": _milliseconds(
                        wall["population_std_ns"]
                    ),
                }
            )


def _format_seconds(value: float) -> str:
    return f"{value * 1000:.1f} ms" if value < 1.0 else f"{value:.1f} s"


def _write_figure(summary: dict[str, Any], path: Path) -> None:
    figure, (span_axis, stage_axis) = plt.subplots(
        1,
        2,
        figsize=(16.5, 8.5),
        gridspec_kw={"width_ratios": [0.8, 1.45]},
    )
    spans = summary["spans"]
    span_seconds = [float(item["median_wall_time_ms"]) / 1000.0 for item in spans]
    span_positions = list(range(len(spans)))
    span_bars = span_axis.barh(
        span_positions,
        span_seconds,
        color=["#6B7280", "#4C78A8", "#F58518", "#7A5195"],
    )
    span_axis.set_yticks(
        span_positions,
        [SPAN_LABELS[item["span_id"]] for item in spans],
    )
    span_axis.invert_yaxis()
    span_axis.set_xlabel("Median wall time (seconds)")
    span_axis.set_title("Additive groups", pad=12)
    span_axis.xaxis.grid(True, color="#D9D9D9", linewidth=0.7)
    span_axis.set_axisbelow(True)
    for bar, value in zip(span_bars, span_seconds, strict=True):
        span_axis.text(
            value + max(span_seconds) * 0.02,
            bar.get_y() + bar.get_height() / 2,
            _format_seconds(value),
            va="center",
            fontsize=9,
        )

    stages = summary["stages"]
    stage_seconds = [_seconds_from_stage(item) for item in stages]
    stage_positions = list(range(len(stages)))
    colors = ["#4C78A8" if item["stage_id"].startswith("m4-") else "#F58518" for item in stages]
    stage_bars = stage_axis.barh(stage_positions, stage_seconds, color=colors)
    stage_axis.set_yticks(
        stage_positions,
        [STAGE_LABELS[item["stage_id"]] for item in stages],
    )
    stage_axis.invert_yaxis()
    stage_axis.set_xscale("log")
    stage_axis.set_xlabel("Median wall time (seconds, logarithmic scale)")
    stage_axis.set_title("Measured stages", pad=12)
    stage_axis.xaxis.grid(True, which="both", color="#D9D9D9", linewidth=0.7)
    stage_axis.set_axisbelow(True)
    for bar, value in zip(stage_bars, stage_seconds, strict=True):
        stage_axis.text(
            value * 1.08,
            bar.get_y() + bar.get_height() / 2,
            _format_seconds(value),
            va="center",
            fontsize=8.5,
        )
    figure.suptitle(
        "Containerized M4–M5 runtime overhead — verified three-trial WSL2 run",
        fontsize=15,
        y=1.01,
    )
    figure.text(
        0.5,
        -0.015,
        (
            "Fresh trust/TPM state per trial; build excluded. Bind-mounted submissions, "
            "swtpm rather than physical TPM; medians are descriptive over n=3 trials."
        ),
        ha="center",
        fontsize=9,
        color="#444444",
    )
    figure.tight_layout()
    figure.savefig(
        path,
        dpi=180,
        bbox_inches="tight",
        metadata={"Software": "fl-forensics runtime-overhead result renderer"},
    )
    plt.close(figure)


def _stage(summary: dict[str, Any], stage_id: str) -> dict[str, Any]:
    return next(item for item in summary["stages"] if item["stage_id"] == stage_id)


def _span(summary: dict[str, Any], span_id: str) -> dict[str, Any]:
    return next(item for item in summary["spans"] if item["span_id"] == span_id)


def _seconds(value: dict[str, Any]) -> float:
    return float(value["median_wall_time_ms"]) / 1000.0


def _write_readme(
    *, summary: dict[str, Any], source_manifest: dict[str, Any], source_manifest_sha256: str, path: Path
) -> None:
    environment = summary["environment"]
    sign = _stage(summary, "m4-swtpm-esk-sign-probe")
    table_rows = [
        ("Fresh M4 bootstrap", _seconds(_span(summary, "bootstrap"))),
        (
            "Trust-related group, including diagnostic ESK probe",
            _seconds(_span(summary, "trust-gate")),
        ),
        ("Secure M5 round", _seconds(_span(summary, "secure-round"))),
        ("All measured stages", _seconds(_span(summary, "measured-total"))),
        (
            "Provision 15 independent swtpm clients",
            _seconds(_stage(summary, "m4-swtpm-provisioning-15-clients")),
        ),
        (
            "Generate 15 TPM Quotes sequentially",
            _seconds(_stage(summary, "m4-swtpm-quote-generation-15-clients")),
        ),
        (
            "Train, validate, and TPM-sign 15 clients (4 workers)",
            _seconds(_stage(summary, "m5-client-train-validate-sign-15-clients")),
        ),
        ("Admission and FedAvg", _seconds(_stage(summary, "m5-admission-fedavg"))),
        (
            "Independent secure-round verification",
            _seconds(_stage(summary, "m5-independent-round-verification")),
        ),
    ]
    table = "\n".join(f"| {label} | median `{value:.3f} s` |" for label, value in table_rows)
    text = f"""# Verified M4–M5 containerized-runtime overhead

This sanitized snapshot publishes the verified three-trial runtime measurement of the local
M4/M5 prototype. Every trial created fresh trust authorities, 15 independent `swtpm` states,
15 enrollments and TLS identities, 15 one-use Quotes, 15 TPM-signed Update Bundles, and one
independently reproduced FedAvg checkpoint. All 36 configured stage executions passed.

The run used CPython {environment['python_version']}, Docker Engine
{environment['docker_server_version']}, and WSL2 Linux on x86-64 with
{environment['logical_cpu_count']} logical CPUs. Docker image construction was excluded from
the timed lifecycle.

## Main measurements

| Scope | Wall-time result |
|---|---:|
{table}
| Direct ESK signature through `tpm2_sign` | median `{sign['internal_sign_median_ms_across_trials']:.3f} ms`; 60 measured signatures |
| 15 real loopback TLS 1.3 mTLS handshakes | median `{_seconds(_stage(summary, 'm4-mtls-15-handshakes')):.3f} s` total |

![Median containerized runtime wall time](runtime-wall-time.png)

Provisioning and sequential Quote generation dominate the M4 path. The direct TPM signing
operation is small by comparison: the approximately six-second external probe stage also
contains container startup, Python startup, two warmups, and 20 measured signatures per
trial. The 15-client M5 stage includes local training, validation, model serialization, ESK
signing, container scheduling, and writes to isolated submission directories.

## Correct interpretation

- `swtpm` exercises the TPM protocol and key-role implementation but is not a physical-TPM
  latency or hardware non-exportability result.
- Signed updates move through separate bind-mounted submission directories. No HTTP/gRPC
  contribution API, WAN transfer, broker, queue, or remote object store was measured.
- `trust-gate` includes the diagnostic ESK probe. `measured-total` is total benchmark work,
  not the latency of one ordinary contribution request.
- Stage CPU fields in `summary.json` measure the host orchestrator and Docker CLI processes;
  they do not represent total CPU consumed inside Docker containers.
- With only three independent trials, medians, ranges, and population standard deviations are
  descriptive. They are not confidence intervals or broad hardware-performance claims.
- This one-round overhead experiment performs client train and validation only. It never opens
  pooled test, benign-only temporal holdout, or client-local test artifacts; those remain
  post-selection operations of the verified 30-round reference campaign.

## Receipt and published files

- benchmark: `{summary['benchmark_id']}`;
- receipt: `{source_manifest['receipt_id']}`;
- source runtime manifest SHA-256: `{source_manifest_sha256}`;
- source configuration SHA-256: `{source_manifest['config_sha256']}`;
- source implementation SHA-256: `{source_manifest['implementation_sha256']}`;
- source samples SHA-256: `{source_manifest['samples_sha256']}`;
- source summary SHA-256: `{source_manifest['summary_sha256']}`.

`summary.json` is copied byte-for-byte from the verified receipt workspace. `stages.csv` and
`spans.csv` are compact derived tables, `runtime-wall-time.png` visualizes the medians, and
`receipt.json` records the successful verification and source hashes. `manifest.json` binds
all six published payload files.

Raw samples and command logs, enrollment records, challenges, Quote evidence, certificates,
client updates, model checkpoints, coordinator keys, and Docker TPM state remain under the
Git-ignored `artifacts/` and Docker volumes. They are deliberately not published.
"""
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()
    verification = verify_runtime_overhead_receipt(
        workspace=arguments.workspace,
        config_path=arguments.config,
    )
    if verification["status"] != "verified":
        raise ValueError(f"runtime receipt is not verified: {verification['errors']}")
    output = arguments.output_dir
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"published output must be new or empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    summary_path = arguments.workspace / "summary.json"
    source_manifest_path = arguments.workspace / "manifest.json"
    summary = _load(summary_path)
    source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    (output / "summary.json").write_bytes(summary_path.read_bytes())
    _write_stage_csv(summary, output / "stages.csv")
    _write_span_csv(summary, output / "spans.csv")
    _write_figure(summary, output / "runtime-wall-time.png")
    receipt = {
        "schema_version": "1.0",
        "artifact_type": "runtime_overhead_published_receipt",
        "benchmark_id": summary["benchmark_id"],
        "profile": summary["profile"],
        "receipt_id": source_manifest["receipt_id"],
        "status": "verified",
        "trial_count": summary["trial_count"],
        "stage_count": summary["stage_count"],
        "completed_at": summary["completed_at"],
        "environment": summary["environment"],
        "methodology": summary["methodology"],
        "source": {
            "manifest_sha256": sha256_file(source_manifest_path),
            "config_sha256": source_manifest["config_sha256"],
            "implementation_sha256": source_manifest["implementation_sha256"],
            "samples_sha256": source_manifest["samples_sha256"],
            "summary_sha256": source_manifest["summary_sha256"],
        },
        "verification": {
            key: verification[key]
            for key in (
                "error_count",
                "runtime_evidence_recomputed",
                "source_snapshots_recomputed",
                "statistics_recomputed",
                "implementation_binding_verified",
            )
        },
    }
    (output / "receipt.json").write_bytes(canonical_json_bytes(receipt) + b"\n")
    _write_readme(
        summary=summary,
        source_manifest=source_manifest,
        source_manifest_sha256=sha256_file(source_manifest_path),
        path=output / "README.md",
    )
    published_files = []
    for name in (
        "README.md",
        "summary.json",
        "stages.csv",
        "spans.csv",
        "runtime-wall-time.png",
        "receipt.json",
    ):
        path = output / name
        published_files.append(
            {"path": name, "size_bytes": path.stat().st_size, "sha256": sha256_file(path)}
        )
    manifest_core = {
        "schema_version": "1.0",
        "artifact_type": "runtime_overhead_published_manifest",
        "benchmark_id": summary["benchmark_id"],
        "source_receipt_id": source_manifest["receipt_id"],
        "files": published_files,
    }
    manifest = {
        **manifest_core,
        "manifest_id": f"runtime-overhead-published-{digest_object(manifest_core)[:24]}",
    }
    (output / "manifest.json").write_bytes(canonical_json_bytes(manifest) + b"\n")
    print(
        json.dumps(
            {
                "status": "published",
                "workspace": str(output),
                "receipt_id": source_manifest["receipt_id"],
                "published_file_count": len(published_files),
                "manifest_sha256": sha256_file(output / "manifest.json"),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
