"""Deterministic, independently verifiable reporting for M6 sensitivity evidence."""

from __future__ import annotations

import csv
import io
import os
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import sha256_bytes, sha256_file
from .preprocessing import derived_json_bytes
from .prototype_sensitivity import verify_prototype_sensitivity
from .storage import load_json, write_once


class PrototypeSensitivityReportingError(RuntimeError):
    """Raised when the source campaign or a derived report is invalid."""


REPORT_FILENAMES = (
    "sensitivity.csv",
    "summary.md",
    "figures/f-sweep-source-recall-delta.png",
    "figures/scale-sweep-source-recall-delta.png",
    "figures/f-sweep-macro-f1-delta.png",
    "figures/scale-sweep-macro-f1-delta.png",
    "figures/f-sweep-prototype-shift.png",
    "figures/scale-sweep-prototype-shift.png",
)


def _plotting_dependencies() -> tuple[Any, Any]:
    cache_root = Path(tempfile.gettempdir()) / "fl-forensics-matplotlib"
    cache_root.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(cache_root))
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise PrototypeSensitivityReportingError(
            'prototype reporting requires: python -m pip install -e ".[reporting]"'
        ) from exc
    return matplotlib, plt


def _figure_bytes(fig: Any, *, plt: Any) -> bytes:
    buffer = io.BytesIO()
    fig.savefig(
        buffer,
        format="png",
        dpi=180,
        bbox_inches="tight",
        facecolor="white",
        metadata={"Software": f"fl-forensics {__version__}"},
    )
    plt.close(fig)
    return buffer.getvalue()


def _validated_source(
    *,
    source_round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    sensitivity_workspace: Path,
    config_path: Path,
) -> tuple[dict[str, Any], dict[str, str]]:
    verification = verify_prototype_sensitivity(
        source_round_workspace=source_round_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        workspace=sensitivity_workspace,
        config_path=config_path,
    )
    if verification.get("status") != "verified":
        errors = verification.get("errors", [])
        detail = "; ".join(str(item) for item in errors) or "unknown error"
        raise PrototypeSensitivityReportingError(
            f"source sensitivity campaign is not verified: {detail}"
        )

    sensitivity_path = sensitivity_workspace / "sensitivity.json"
    manifest_path = sensitivity_workspace / "manifest.json"
    sensitivity = load_json(sensitivity_path)
    manifest = load_json(manifest_path)
    if sensitivity.get("artifact_type") != "m6_prototype_poisoning_sensitivity":
        raise PrototypeSensitivityReportingError("unexpected sensitivity artifact type")
    if manifest.get("artifact_type") != (
        "m6_prototype_poisoning_sensitivity_manifest"
    ):
        raise PrototypeSensitivityReportingError("unexpected sensitivity manifest type")
    sensitivity_sha256 = sha256_file(sensitivity_path)
    if manifest.get("sensitivity_sha256") != sensitivity_sha256:
        raise PrototypeSensitivityReportingError("source sensitivity digest mismatch")
    if sensitivity.get("scenario_count") != len(sensitivity.get("scenarios", [])):
        raise PrototypeSensitivityReportingError("source scenario count mismatch")
    if sensitivity.get("report_every_scenario") is not True:
        raise PrototypeSensitivityReportingError("source does not preserve every scenario")
    if sensitivity.get("selection_performed") is not False:
        raise PrototypeSensitivityReportingError("source reports post-test selection")
    if sensitivity.get("test_based_selection_permitted") is not False:
        raise PrototypeSensitivityReportingError("source permits test-based selection")
    return sensitivity, {
        "source_manifest_sha256": sha256_file(manifest_path),
        "source_sensitivity_sha256": sensitivity_sha256,
        "campaign_config_sha256": str(sensitivity["campaign_config_sha256"]),
    }


def _rows(sensitivity: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    scenarios = sorted(
        sensitivity["scenarios"],
        key=lambda item: (int(item["f"]), float(item["scale"])),
    )
    for scenario in scenarios:
        for profile_name, profile_key in (
            ("baseline", "baseline"),
            ("robust", "robust"),
        ):
            values = scenario[profile_key]
            rows.append(
                {
                    "scenario_id": str(scenario["scenario_id"]),
                    "primary_anchor": bool(scenario["primary_anchor"]),
                    "f": int(scenario["f"]),
                    "scale": float(scenario["scale"]),
                    "profile": profile_name,
                    "aggregation_strategy": str(values["aggregation_strategy"]),
                    "source_prototype_shift_l2": float(
                        values["source_prototype_shift_l2"]
                    ),
                    "validation_macro_f1_delta": float(
                        values["validation_macro_f1_delta"]
                    ),
                    "test_macro_f1_delta": float(values["test_macro_f1_delta"]),
                    "validation_source_recall_delta": float(
                        values["validation_source_recall_delta"]
                    ),
                    "test_source_recall_delta": float(
                        values["test_source_recall_delta"]
                    ),
                    "test_source_misclassification_rate_delta": float(
                        values["test_source_misclassification_rate_delta"]
                    ),
                    "test_targeted_attack_success_rate_delta": float(
                        values["test_targeted_attack_success_rate_delta"]
                    ),
                    "clean_test_macro_f1": float(values["clean_test_macro_f1"]),
                    "attacked_test_macro_f1": float(
                        values["attacked_test_macro_f1"]
                    ),
                    "clean_test_source_recall": float(
                        values["clean_test_source_recall"]
                    ),
                    "attacked_test_source_recall": float(
                        values["attacked_test_source_recall"]
                    ),
                    "attacked_test_targeted_attack_success_rate": float(
                        values["attacked_test_targeted_attack_success_rate"]
                    ),
                    "attacked_test_other_class_misclassification_rate": float(
                        values["attacked_test_other_class_misclassification_rate"]
                    ),
                }
            )
    if len(rows) != 2 * int(sensitivity["scenario_count"]):
        raise PrototypeSensitivityReportingError("report row count mismatch")
    return rows


def _csv_bytes(rows: list[dict[str, Any]]) -> bytes:
    columns = list(rows[0])
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        serialized = {
            key: format(value, ".17g") if isinstance(value, float) else value
            for key, value in row.items()
        }
        writer.writerow(serialized)
    return buffer.getvalue().encode("utf-8")


def _primary_rows(
    rows: list[dict[str, Any]], primary_scenario_id: str
) -> dict[str, dict[str, Any]]:
    result = {
        str(row["profile"]): row
        for row in rows
        if row["scenario_id"] == primary_scenario_id
    }
    if sorted(result) != ["baseline", "robust"]:
        raise PrototypeSensitivityReportingError("primary scenario profiles are incomplete")
    return result


def _observations(
    rows: list[dict[str, Any]], primary_scenario_id: str
) -> dict[str, Any]:
    baseline = [row for row in rows if row["profile"] == "baseline"]
    robust = [row for row in rows if row["profile"] == "robust"]
    worst = min(baseline, key=lambda row: row["test_source_recall_delta"])
    primary = _primary_rows(rows, primary_scenario_id)
    return {
        "descriptive_extrema_not_selection": True,
        "largest_observed_baseline_test_source_recall_loss": {
            "scenario_id": worst["scenario_id"],
            "delta": worst["test_source_recall_delta"],
            "attacked_recall": worst["attacked_test_source_recall"],
        },
        "maximum_absolute_robust_test_source_recall_delta": max(
            abs(row["test_source_recall_delta"]) for row in robust
        ),
        "maximum_observed_targeted_test_attack_success_rate": max(
            row["attacked_test_targeted_attack_success_rate"] for row in rows
        ),
        "primary_anchor": {
            "scenario_id": primary_scenario_id,
            "baseline_test_source_recall_delta": primary["baseline"][
                "test_source_recall_delta"
            ],
            "baseline_test_macro_f1_delta": primary["baseline"][
                "test_macro_f1_delta"
            ],
            "robust_test_source_recall_delta": primary["robust"][
                "test_source_recall_delta"
            ],
            "robust_test_macro_f1_delta": primary["robust"][
                "test_macro_f1_delta"
            ],
        },
    }


def _sweep_rows(
    rows: list[dict[str, Any]],
    *,
    sweep: str,
    primary_f: int,
    primary_scale: float,
) -> list[dict[str, Any]]:
    if sweep == "f":
        result = [row for row in rows if row["scale"] == primary_scale]
        return sorted(result, key=lambda row: (row["f"], row["profile"]))
    result = [row for row in rows if row["f"] == primary_f]
    return sorted(result, key=lambda row: (row["scale"], row["profile"]))


def _curve(
    *,
    plt: Any,
    rows: list[dict[str, Any]],
    sweep: str,
    metric: str,
    ylabel: str,
    title: str,
) -> Any:
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    x_key = "f" if sweep == "f" else "scale"
    style = {
        "baseline": ("#b91c1c", "o", "Support-weighted mean"),
        "robust": ("#166534", "s", "Coordinate median"),
    }
    for profile in ("baseline", "robust"):
        selected = [row for row in rows if row["profile"] == profile]
        color, marker, label = style[profile]
        ax.plot(
            [row[x_key] for row in selected],
            [row[metric] for row in selected],
            color=color,
            marker=marker,
            linewidth=2.0,
            markersize=6,
            label=label,
        )
    if metric.endswith("delta"):
        ax.axhline(0.0, color="#475569", linewidth=1.0, linestyle="--")
    ax.set_xlabel("Byzantine clients (f)" if sweep == "f" else "Poisoning scale")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(axis="both", color="#d8dee9", linewidth=0.8, alpha=0.75)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(frameon=False)
    if sweep == "f":
        ax.set_xticks(sorted({int(row["f"]) for row in rows}))
    else:
        ax.set_xticks(sorted({float(row["scale"]) for row in rows}))
    fig.tight_layout()
    return fig


def _markdown_bytes(
    *,
    sensitivity: dict[str, Any],
    rows: list[dict[str, Any]],
    observations: dict[str, Any],
) -> bytes:
    lines = [
        "# M6 prototype-poisoning sensitivity report",
        "",
        "This deterministic report describes every predeclared scenario. It does not",
        "rank or select a configuration from test performance.",
        "",
        f"- Analysis: `{sensitivity['analysis_type']}`",
        f"- Scenarios: {sensitivity['scenario_count']}",
        f"- Primary anchor: `{sensitivity['primary_scenario_id']}`",
        "- Test-based selection permitted: no",
        "- Selection performed: no",
        "- Test data accessed: yes",
        "",
        "## Complete report-all table",
        "",
        "| Scenario | f | Scale | Aggregation | Prototype shift | Test recall delta | Test macro-F1 delta | Test targeted ASR |",
        "| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            "| {scenario_id} | {f} | {scale:.1f} | {aggregation_strategy} | "
            "{source_prototype_shift_l2:.6f} | {test_source_recall_delta:.6f} | "
            "{test_macro_f1_delta:.6f} | "
            "{attacked_test_targeted_attack_success_rate:.6f} |".format(**row)
        )
    worst = observations["largest_observed_baseline_test_source_recall_loss"]
    lines.extend(
        [
            "",
            "## Descriptive observations",
            "",
            (
                "The largest observed baseline source-recall loss occurs in "
                f"`{worst['scenario_id']}`: delta {worst['delta']:.6f}, with "
                f"attacked recall {worst['attacked_recall']:.6f}. This is a "
                "descriptive extremum, not a selected configuration."
            ),
            "",
            (
                "The maximum absolute coordinate-median source-recall delta is "
                f"{observations['maximum_absolute_robust_test_source_recall_delta']:.6f}."
            ),
            "",
            (
                "The maximum observed targeted test attack-success rate is "
                f"{observations['maximum_observed_targeted_test_attack_success_rate']:.6f}. "
                "Source-recall loss and non-target errors must therefore be interpreted "
                "separately from targeted ASR."
            ),
            "",
            "The source campaign retains the full confusion matrices and per-class metrics",
            "for every scenario; this report is a deterministic cross-scenario view.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def _artifact_record(path: str, content: bytes, description: str) -> dict[str, Any]:
    return {
        "path": path,
        "description": description,
        "sha256": sha256_bytes(content),
        "size_bytes": len(content),
    }


def _build_report(
    *,
    sensitivity: dict[str, Any],
    source_digests: dict[str, str],
    rendering_backend: dict[str, Any],
    plt: Any,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    rows = _rows(sensitivity)
    observations = _observations(rows, str(sensitivity["primary_scenario_id"]))
    primary_scenario = next(
        item
        for item in sensitivity["scenarios"]
        if item["scenario_id"] == sensitivity["primary_scenario_id"]
    )
    primary_f = int(primary_scenario["f"])
    primary_scale = float(primary_scenario["scale"])
    f_rows = _sweep_rows(
        rows, sweep="f", primary_f=primary_f, primary_scale=primary_scale
    )
    scale_rows = _sweep_rows(
        rows, sweep="scale", primary_f=primary_f, primary_scale=primary_scale
    )
    if len(f_rows) != 6 or len(scale_rows) != 8:
        raise PrototypeSensitivityReportingError("unexpected one-factor sweep shape")

    artifacts: dict[str, bytes] = {
        "sensitivity.csv": _csv_bytes(rows),
        "summary.md": _markdown_bytes(
            sensitivity=sensitivity, rows=rows, observations=observations
        ),
    }
    figures = (
        (
            "figures/f-sweep-source-recall-delta.png",
            f_rows,
            "f",
            "test_source_recall_delta",
            "Test source-recall delta",
            "Source recall under increasing Byzantine participation",
        ),
        (
            "figures/scale-sweep-source-recall-delta.png",
            scale_rows,
            "scale",
            "test_source_recall_delta",
            "Test source-recall delta",
            "Source recall under increasing poisoning scale",
        ),
        (
            "figures/f-sweep-macro-f1-delta.png",
            f_rows,
            "f",
            "test_macro_f1_delta",
            "Test macro-F1 delta",
            "Macro-F1 under increasing Byzantine participation",
        ),
        (
            "figures/scale-sweep-macro-f1-delta.png",
            scale_rows,
            "scale",
            "test_macro_f1_delta",
            "Test macro-F1 delta",
            "Macro-F1 under increasing poisoning scale",
        ),
        (
            "figures/f-sweep-prototype-shift.png",
            f_rows,
            "f",
            "source_prototype_shift_l2",
            "Source prototype shift (L2)",
            "Prototype displacement under increasing Byzantine participation",
        ),
        (
            "figures/scale-sweep-prototype-shift.png",
            scale_rows,
            "scale",
            "source_prototype_shift_l2",
            "Source prototype shift (L2)",
            "Prototype displacement under increasing poisoning scale",
        ),
    )
    for path, figure_rows, sweep, metric, ylabel, title in figures:
        artifacts[path] = _figure_bytes(
            _curve(
                plt=plt,
                rows=figure_rows,
                sweep=sweep,
                metric=metric,
                ylabel=ylabel,
                title=title,
            ),
            plt=plt,
        )

    descriptions = {
        "sensitivity.csv": "machine-readable report-all scenario and strategy table",
        "summary.md": "human-readable report-all interpretation",
        "figures/f-sweep-source-recall-delta.png": "source recall versus f",
        "figures/scale-sweep-source-recall-delta.png": "source recall versus scale",
        "figures/f-sweep-macro-f1-delta.png": "macro-F1 versus f",
        "figures/scale-sweep-macro-f1-delta.png": "macro-F1 versus scale",
        "figures/f-sweep-prototype-shift.png": "prototype shift versus f",
        "figures/scale-sweep-prototype-shift.png": "prototype shift versus scale",
    }
    report = {
        "schema_version": "1.0",
        "artifact_type": "m6_prototype_poisoning_sensitivity_report",
        "analysis_type": sensitivity["analysis_type"],
        "scenario_count": int(sensitivity["scenario_count"]),
        "row_count": len(rows),
        "figure_count": len(figures),
        "primary_scenario_id": sensitivity["primary_scenario_id"],
        "report_every_scenario": True,
        "test_based_selection_permitted": False,
        "selection_performed": False,
        "test_data_accessed": True,
        "source": source_digests,
        "rendering_backend": rendering_backend,
        "observations": observations,
        "artifacts": [
            _artifact_record(path, artifacts[path], descriptions[path])
            for path in REPORT_FILENAMES
        ],
    }
    return artifacts, report


def _manifest(
    *,
    report_sha256: str,
    source_digests: dict[str, str],
    implementation_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "artifact_type": "m6_prototype_poisoning_sensitivity_report_manifest",
        "code_version": __version__,
        "report_path": "report.json",
        "report_sha256": report_sha256,
        "source": source_digests,
        "implementation_sha256": implementation_sha256,
        "report_every_scenario": True,
        "test_based_selection_permitted": False,
        "selection_performed": False,
        "test_data_accessed": True,
    }


def generate_prototype_sensitivity_report(
    *,
    source_round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    sensitivity_workspace: Path,
    output: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Generate immutable tables and figures only after source recomputation."""

    sensitivity, source_digests = _validated_source(
        source_round_workspace=source_round_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        sensitivity_workspace=sensitivity_workspace,
        config_path=config_path,
    )
    matplotlib, plt = _plotting_dependencies()
    rendering_backend = {
        "name": "matplotlib",
        "version": str(matplotlib.__version__),
        "format": "png",
        "dpi": 180,
    }
    artifacts, report = _build_report(
        sensitivity=sensitivity,
        source_digests=source_digests,
        rendering_backend=rendering_backend,
        plt=plt,
    )
    for relative_path in REPORT_FILENAMES:
        write_once(output / relative_path, artifacts[relative_path])
    report_content = derived_json_bytes(report)
    write_once(output / "report.json", report_content)
    report_sha256 = sha256_bytes(report_content)
    manifest = _manifest(
        report_sha256=report_sha256,
        source_digests=source_digests,
        implementation_sha256=sha256_file(Path(__file__)),
    )
    manifest_content = derived_json_bytes(manifest)
    write_once(output / "manifest.json", manifest_content)
    return {
        "status": "reported_verified_source",
        "analysis_type": report["analysis_type"],
        "scenario_count": report["scenario_count"],
        "row_count": report["row_count"],
        "figure_count": report["figure_count"],
        "primary_scenario_id": report["primary_scenario_id"],
        "selection_performed": False,
        "test_data_accessed": True,
        "report_sha256": report_sha256,
        "manifest_sha256": sha256_bytes(manifest_content),
        "workspace": str(output),
    }


def verify_prototype_sensitivity_report(
    *,
    source_round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    sensitivity_workspace: Path,
    report_workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Recompute the source evidence and every byte of the derived report."""

    errors: list[str] = []
    stored_report: dict[str, Any] = {}
    source_recomputed = False
    report_path = report_workspace / "report.json"
    manifest_path = report_workspace / "manifest.json"
    try:
        sensitivity, source_digests = _validated_source(
            source_round_workspace=source_round_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            sensitivity_workspace=sensitivity_workspace,
            config_path=config_path,
        )
        source_recomputed = True
        stored_report = load_json(report_path)
        load_json(manifest_path)
        matplotlib, plt = _plotting_dependencies()
        rendering_backend = {
            "name": "matplotlib",
            "version": str(matplotlib.__version__),
            "format": "png",
            "dpi": 180,
        }
        expected_artifacts, expected_report = _build_report(
            sensitivity=sensitivity,
            source_digests=source_digests,
            rendering_backend=rendering_backend,
            plt=plt,
        )
        expected_report_content = derived_json_bytes(expected_report)
        if report_path.read_bytes() != expected_report_content:
            errors.append("report.json differs from deterministic recomputation")
        for relative_path in REPORT_FILENAMES:
            path = report_workspace / relative_path
            if not path.is_file():
                errors.append(f"missing report artifact: {relative_path}")
            elif path.read_bytes() != expected_artifacts[relative_path]:
                errors.append(f"report artifact differs from recomputation: {relative_path}")
        expected_manifest = _manifest(
            report_sha256=sha256_bytes(expected_report_content),
            source_digests=source_digests,
            implementation_sha256=sha256_file(Path(__file__)),
        )
        if manifest_path.read_bytes() != derived_json_bytes(expected_manifest):
            errors.append("report manifest differs from deterministic recomputation")
        expected_paths = {
            *REPORT_FILENAMES,
            "report.json",
            "manifest.json",
        }
        actual_paths = {
            path.relative_to(report_workspace).as_posix()
            for path in report_workspace.rglob("*")
            if path.is_file()
        }
        unexpected = sorted(actual_paths - expected_paths)
        if unexpected:
            errors.append(f"unexpected report artifacts: {', '.join(unexpected)}")
    except (
        KeyError,
        OSError,
        PrototypeSensitivityReportingError,
        StopIteration,
        TypeError,
        ValueError,
    ) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "analysis_type": stored_report.get("analysis_type"),
        "scenario_count": stored_report.get("scenario_count"),
        "row_count": stored_report.get("row_count"),
        "figure_count": stored_report.get("figure_count"),
        "primary_scenario_id": stored_report.get("primary_scenario_id"),
        "selection_performed": stored_report.get("selection_performed"),
        "test_data_accessed": stored_report.get("test_data_accessed"),
        "report_sha256": sha256_file(report_path) if report_path.is_file() else None,
        "manifest_sha256": (
            sha256_file(manifest_path) if manifest_path.is_file() else None
        ),
        "source_recomputed": source_recomputed,
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(report_workspace),
    }
