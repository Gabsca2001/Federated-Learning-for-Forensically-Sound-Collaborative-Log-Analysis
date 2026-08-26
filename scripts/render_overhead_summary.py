#!/usr/bin/env python3
"""Render the compact public table and figure for an overhead summary."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt

plt.switch_backend("Agg")


LABELS = {
    "m4-software-ecdsa-sign-verify": "M4 software ECDSA\n1,000 sign/verify pairs",
    "m4-attestation-receipt-verification": "M4 receipt verification\n15 enrollments + 105 results",
    "m5-campaign-verification": "M5 campaign verification\n30 rounds / 450 contributions",
    "m7-prediction-verification": "M7 prediction verification\n6 cases",
    "m7-explanation-verification": "M7 explanation verification\n6 cases",
    "m7-attack-verification": "M7 ATT&CK verification\n6 mappings",
    "m7-report-verification": "M7 report verification\n6 cases",
    "m8-preservation-verification": "M8 preservation verification\n2,381 artifacts",
    "m8-merkle-verification": "M8 Merkle verification\n2,388 leaves",
    "m8-timestamp-verification": "M8 timestamp verification\noffline RFC 3161",
    "m8-recovery-verification": "M8 recovery verification\n2,381 payload entries",
    "m8-accounting-verification": "M8 accounting verification\n30 rounds / 450 contributions",
    "m8-final-preservation-verification": "M8 final verification\n5 assurance stages",
}


def _color(stage_id: str) -> str:
    if stage_id.startswith("m4-"):
        return "#4C78A8"
    if stage_id.startswith("m5-"):
        return "#F58518"
    if stage_id.startswith("m7-"):
        return "#54A24B"
    return "#B279A2"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("artifact_type") != "m4_m8_offline_overhead_summary":
        raise ValueError("not an M4--M8 overhead summary")
    stages = value.get("stages")
    if not isinstance(stages, list) or [item.get("stage_id") for item in stages] != list(
        LABELS
    ):
        raise ValueError("overhead stage set or ordering mismatch")
    return value


def _milliseconds(value: float | None) -> float | str:
    return "" if value is None else float(value) / 1_000_000.0


def _write_csv(summary: dict[str, Any], path: Path) -> None:
    columns = [
        "stage_id",
        "scope",
        "warmup_runs",
        "repetitions",
        "operations_per_sample",
        "median_wall_time_ms",
        "mean_wall_time_ms",
        "p95_wall_time_ms",
        "minimum_wall_time_ms",
        "maximum_wall_time_ms",
        "sample_standard_deviation_ms",
        "median_cpu_time_ms",
        "mean_wall_time_microseconds_per_operation",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for stage in summary["stages"]:
            writer.writerow(
                {
                    "stage_id": stage["stage_id"],
                    "scope": stage["scope"],
                    "warmup_runs": stage["warmup_runs"],
                    "repetitions": stage["repetitions"],
                    "operations_per_sample": stage["operations_per_sample"],
                    "median_wall_time_ms": stage["median_wall_time_ms"],
                    "mean_wall_time_ms": stage["mean_wall_time_ms"],
                    "p95_wall_time_ms": stage["p95_wall_time_ms"],
                    "minimum_wall_time_ms": _milliseconds(
                        stage["wall_time_ns"]["minimum"]
                    ),
                    "maximum_wall_time_ms": _milliseconds(
                        stage["wall_time_ns"]["maximum"]
                    ),
                    "sample_standard_deviation_ms": _milliseconds(
                        stage["wall_time_ns"]["sample_standard_deviation"]
                    ),
                    "median_cpu_time_ms": _milliseconds(
                        stage["cpu_time_ns"]["median"]
                    ),
                    "mean_wall_time_microseconds_per_operation": stage[
                        "mean_wall_time_microseconds_per_operation"
                    ],
                }
            )


def _format_seconds(value: float) -> str:
    if value < 0.1:
        return f"{value * 1000:.1f} ms"
    if value < 1.0:
        return f"{value:.3f} s"
    return f"{value:.1f} s"


def _write_figure(summary: dict[str, Any], path: Path) -> None:
    stages = summary["stages"]
    labels = [LABELS[item["stage_id"]] for item in stages]
    seconds = [float(item["median_wall_time_ms"]) / 1000.0 for item in stages]
    colors = [_color(item["stage_id"]) for item in stages]

    figure, axis = plt.subplots(figsize=(12.5, 8.2))
    positions = list(range(len(stages)))
    bars = axis.barh(positions, seconds, color=colors, edgecolor="white", linewidth=0.8)
    axis.set_yticks(positions, labels)
    axis.invert_yaxis()
    axis.set_xscale("log")
    axis.set_xlabel("Median warm-process wall time (seconds, logarithmic scale)")
    axis.set_title("Offline verifier latency — verified WSL2 reference run", pad=14)
    axis.xaxis.grid(True, which="both", color="#D9D9D9", linewidth=0.7)
    axis.set_axisbelow(True)
    for bar, value in zip(bars, seconds, strict=True):
        axis.text(
            value * 1.08,
            bar.get_y() + bar.get_height() / 2,
            _format_seconds(value),
            va="center",
            fontsize=9,
        )
    axis.text(
        0.0,
        -0.13,
        (
            "M4–M7 bars are medians of repeated samples; M8 bars are single I/O-heavy "
            "observations. Stages reverify upstream sources and are not additive."
        ),
        transform=axis.transAxes,
        fontsize=9,
        color="#444444",
    )
    figure.tight_layout()
    figure.savefig(
        path,
        dpi=180,
        bbox_inches="tight",
        metadata={"Software": "fl-forensics overhead result renderer"},
    )
    plt.close(figure)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()
    summary = _load(arguments.summary)
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(summary, arguments.output_dir / "stages.csv")
    _write_figure(summary, arguments.output_dir / "median-wall-time.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
