"""Auditable measurements for the containerized M4/M5 runtime prototype.

Unlike :mod:`fl_forensics.overhead`, this module records state-changing live
operations.  Each trial therefore needs a fresh trust workspace, fresh node
workspaces, and a unique Docker Compose project.  The verifier never reruns
those operations: it recomputes the statistics and checks their bindings to
the source tree and to the runtime evidence left by every trial.
"""

from __future__ import annotations

import math
import os
import platform
import statistics
import time
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes, digest_object, sha256_bytes, sha256_file
from .config import load_yaml
from .crypto import load_public_key, verify_digest_signature
from .preprocessing import derived_json_bytes
from .storage import load_json, write_once
from .tpm_adapter import ESK_HANDLE, TPM2ToolsSigner


class RuntimeOverheadError(ValueError):
    """Raised when the runtime benchmark contract or receipt is invalid."""


RUNTIME_STAGE_IDS = (
    "m4-trust-initialization",
    "m4-swtpm-provisioning-15-clients",
    "m4-enrollment-15-clients",
    "m4-mtls-15-handshakes",
    "m4-swtpm-esk-sign-probe",
    "m4-challenge-issuance-15-clients",
    "m4-swtpm-quote-generation-15-clients",
    "m4-quote-appraisal-15-clients",
    "m5-round-context-initialization",
    "m5-client-train-validate-sign-15-clients",
    "m5-admission-fedavg",
    "m5-independent-round-verification",
)

SPAN_STAGE_IDS = {
    "bootstrap": RUNTIME_STAGE_IDS[:3],
    "trust-gate": RUNTIME_STAGE_IDS[3:8],
    "secure-round": RUNTIME_STAGE_IDS[8:],
}

_TPM_PROBE_DIGEST = sha256_bytes(
    b"fl-forensics-runtime-overhead-swtpm-esk-sign-probe-v1"
)


def _integer(
    value: Any,
    *,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise RuntimeOverheadError(
            f"{name} must be an integer between {minimum} and {maximum}"
        )
    return value


def load_runtime_overhead_contract(config_path: Path) -> tuple[dict[str, Any], str]:
    contract, digest = load_yaml(config_path)
    if contract.get("schema_version") != "1.0":
        raise RuntimeOverheadError("unsupported runtime overhead schema_version")
    if contract.get("profile") != "containerized-secure-round-runtime-v1":
        raise RuntimeOverheadError("runtime overhead profile mismatch")
    if not str(contract.get("benchmark_id", "")).strip():
        raise RuntimeOverheadError("benchmark_id is required")
    if not isinstance(contract.get("project_root"), str):
        raise RuntimeOverheadError("project_root must be a string")
    if not isinstance(contract.get("project_namespace"), str) or not str(
        contract["project_namespace"]
    ).strip():
        raise RuntimeOverheadError("project_namespace is required")
    for name in (
        "compose_m4",
        "compose_m5",
        "partition_workspace",
        "work_root",
        "trust_config",
        "clients_config",
        "federation_config",
        "secure_round_config",
    ):
        if not isinstance(contract.get(name), str) or not contract[name].strip():
            raise RuntimeOverheadError(f"{name} must be a non-empty path string")
    _integer(contract.get("repetitions"), name="repetitions", minimum=1, maximum=10)
    _integer(contract.get("workers"), name="workers", minimum=1, maximum=15)
    probe = contract.get("tpm_sign_probe")
    if not isinstance(probe, dict):
        raise RuntimeOverheadError("tpm_sign_probe must be an object")
    _integer(
        probe.get("warmup_runs"),
        name="tpm_sign_probe.warmup_runs",
        minimum=0,
        maximum=20,
    )
    _integer(
        probe.get("repetitions"),
        name="tpm_sign_probe.repetitions",
        minimum=1,
        maximum=1_000,
    )
    markers = contract.get("source_markers")
    if not isinstance(markers, list) or not markers:
        raise RuntimeOverheadError("source_markers must be a non-empty list")
    if any(not isinstance(item, str) or not item.strip() for item in markers):
        raise RuntimeOverheadError("source_markers must contain path strings")
    if len(markers) != len(set(markers)):
        raise RuntimeOverheadError("source_markers contain duplicates")
    expected = contract.get("expected")
    if not isinstance(expected, dict) or set(expected) != set(RUNTIME_STAGE_IDS):
        raise RuntimeOverheadError(
            "expected outcomes must cover the exact ordered runtime stage set"
        )
    if any(not isinstance(value, dict) or not value for value in expected.values()):
        raise RuntimeOverheadError("every runtime stage needs expected outcome fields")
    return contract, digest


def project_root(config_path: Path, contract: dict[str, Any]) -> Path:
    return (config_path.resolve().parent / contract["project_root"]).resolve()


def resolve_contract_path(root: Path, value: str) -> Path:
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise RuntimeOverheadError(f"runtime path escapes project root: {value}") from exc
    return candidate


def runtime_environment() -> dict[str, Any]:
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
    }


def benchmark_tpm_esk_sign(
    *,
    node_workspace: Path,
    tcti: str,
    warmup_runs: int,
    repetitions: int,
) -> dict[str, Any]:
    """Measure an already-provisioned ESK without writing benchmark signatures."""

    _integer(warmup_runs, name="warmup_runs", minimum=0, maximum=20)
    _integer(repetitions, name="repetitions", minimum=1, maximum=1_000)
    public_path = node_workspace / "tpm-objects" / "esk.public.pem"
    public_bytes = public_path.read_bytes()
    public_key = load_public_key(public_bytes)
    signer = TPM2ToolsSigner(
        key_context=ESK_HANDLE,
        public_key_pem=public_bytes,
        tcti=tcti,
    )
    samples: list[dict[str, Any]] = []
    total = warmup_runs + repetitions
    for index in range(total):
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        signature = signer.sign_digest(_TPM_PROBE_DIGEST)
        cpu_time = time.process_time_ns() - cpu_start
        wall_time = time.perf_counter_ns() - wall_start
        if not verify_digest_signature(public_key, _TPM_PROBE_DIGEST, signature):
            raise RuntimeOverheadError("swtpm ESK probe signature verification failed")
        samples.append(
            {
                "sample_index": index,
                "warmup": index < warmup_runs,
                "wall_time_ns": wall_time,
                "cpu_time_ns": cpu_time,
                "verified": True,
            }
        )
    measured = [item for item in samples if not item["warmup"]]
    wall_values = [int(item["wall_time_ns"]) for item in measured]
    return {
        "status": "verified",
        "backend": "swtpm-via-tpm2-tools",
        "algorithm": "ECDSA-P256-SHA256",
        "key_handle": ESK_HANDLE,
        "key_id": signer.key_id,
        "digest_sha256": _TPM_PROBE_DIGEST,
        "warmup_count": warmup_runs,
        "measured_sample_count": repetitions,
        "median_sign_wall_time_ms": statistics.median(wall_values) / 1_000_000.0,
        "samples": samples,
    }


def _snapshot(path: Path, *, root: Path) -> dict[str, Any]:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise RuntimeOverheadError(f"snapshot path escapes project root: {path}") from exc
    if path.is_file():
        return {
            "path": relative,
            "kind": "file",
            "entry_count": 1,
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    if not path.is_dir():
        raise FileNotFoundError(f"runtime snapshot input is missing: {path}")
    entries = []
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        entries.append(
            {
                "path": item.relative_to(path).as_posix(),
                "size_bytes": item.stat().st_size,
                "sha256": sha256_file(item),
            }
        )
    return {
        "path": relative,
        "kind": "directory",
        "entry_count": len(entries),
        "size_bytes": sum(int(item["size_bytes"]) for item in entries),
        "sha256": digest_object(entries),
    }


def source_snapshots(
    *, root: Path, contract: dict[str, Any]
) -> list[dict[str, Any]]:
    return [
        _snapshot(resolve_contract_path(root, value), root=root)
        for value in contract["source_markers"]
    ]


def trial_snapshot_paths(trial: dict[str, Any], *, root: Path) -> list[Path]:
    workspaces = trial.get("workspaces")
    if not isinstance(workspaces, dict):
        raise RuntimeOverheadError("runtime trial has no workspace mapping")
    required = {
        "trust_workspace": (
            "manifest.json",
            "baseline/baseline.json",
            "registry/index.json",
            "challenges",
            "results",
        ),
        "round_workspace": (
            "public/round-context.json",
            "submissions",
            "checkpoint/manifest.json",
            "checkpoint/global-model.json",
        ),
    }
    paths: list[Path] = []
    for name, suffixes in required.items():
        value = workspaces.get(name)
        if not isinstance(value, str):
            raise RuntimeOverheadError(f"runtime trial is missing workspace: {name}")
        base = resolve_contract_path(root, value)
        paths.extend(base / suffix for suffix in suffixes)
    node_value = workspaces.get("node_root")
    if not isinstance(node_value, str):
        raise RuntimeOverheadError("runtime trial is missing workspace: node_root")
    node_root = resolve_contract_path(root, node_value)
    for index in range(1, 16):
        node = node_root / f"client{index:02d}"
        paths.extend(
            (
                node / "provisioning_summary.json",
                node / "enrollment_record.json",
                node / "quote_evidence.json",
                node / "tpm-objects" / "esk.public.pem",
            )
        )
    return paths


def trial_snapshots(trial: dict[str, Any], *, root: Path) -> list[dict[str, Any]]:
    return [_snapshot(path, root=root) for path in trial_snapshot_paths(trial, root=root)]


def _assert_expected(actual: dict[str, Any], expected: dict[str, Any], stage_id: str) -> None:
    for key, value in expected.items():
        if actual.get(key) != value:
            raise RuntimeOverheadError(
                f"runtime stage {stage_id} expected {key}={value!r}, "
                f"received {actual.get(key)!r}"
            )


def validate_trials(
    trials: list[dict[str, Any]], contract: dict[str, Any], *, root: Path
) -> None:
    if len(trials) != int(contract["repetitions"]):
        raise RuntimeOverheadError("runtime trial count does not match the contract")
    for expected_index, trial in enumerate(trials, start=1):
        if trial.get("trial_index") != expected_index:
            raise RuntimeOverheadError("runtime trial indexes are not contiguous")
        expected_project = f"{contract['project_namespace']}_{expected_index:03d}"
        if trial.get("compose_project") != expected_project:
            raise RuntimeOverheadError("runtime Compose project does not match the contract")
        trial_root = (
            resolve_contract_path(root, contract["work_root"])
            / f"trial-{expected_index:03d}"
        )
        expected_workspaces = {
            "trust_workspace": (trial_root / "m4-trust").relative_to(root).as_posix(),
            "node_root": (trial_root / "m4-nodes").relative_to(root).as_posix(),
            "round_workspace": (
                trial_root / "m5-secure-round"
            ).relative_to(root).as_posix(),
            "coordinator_workspace": (
                trial_root / "m5-coordinator"
            ).relative_to(root).as_posix(),
        }
        if trial.get("workspaces") != expected_workspaces:
            raise RuntimeOverheadError("runtime trial workspaces do not match the contract")
        expected_order_digest = sha256_bytes("\n".join(RUNTIME_STAGE_IDS).encode())
        if trial.get("stage_order_sha256") != expected_order_digest:
            raise RuntimeOverheadError("runtime stage-order digest mismatch")
        stages = trial.get("stages")
        if not isinstance(stages, list):
            raise RuntimeOverheadError("runtime trial stages must be a list")
        if [item.get("stage_id") for item in stages] != list(RUNTIME_STAGE_IDS):
            raise RuntimeOverheadError("runtime stages are missing, duplicated, or reordered")
        for stage in stages:
            stage_id = stage["stage_id"]
            for key in ("wall_time_ns", "cpu_time_ns"):
                value = stage.get(key)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise RuntimeOverheadError(
                        f"invalid {key} for runtime stage {stage_id}"
                    )
            outcome = stage.get("outcome")
            if not isinstance(outcome, dict):
                raise RuntimeOverheadError(f"runtime stage has no outcome: {stage_id}")
            _assert_expected(outcome, contract["expected"][stage_id], stage_id)
        spans = trial.get("spans")
        expected_spans = {
            name: sum(
                int(stage["wall_time_ns"])
                for stage in stages
                if stage["stage_id"] in stage_ids
            )
            for name, stage_ids in SPAN_STAGE_IDS.items()
        }
        expected_spans["measured-total"] = sum(
            int(stage["wall_time_ns"]) for stage in stages
        )
        if spans != expected_spans:
            raise RuntimeOverheadError("runtime trial span totals are inconsistent")


def _distribution(values: list[int]) -> dict[str, Any]:
    if not values:
        raise RuntimeOverheadError("cannot summarize an empty timing distribution")
    ordered = sorted(values)
    count = len(ordered)
    mean = statistics.fmean(ordered)
    variance = statistics.fmean([(value - mean) ** 2 for value in ordered])
    return {
        "count": count,
        "minimum_ns": ordered[0],
        "maximum_ns": ordered[-1],
        "mean_ns": mean,
        "median_ns": statistics.median(ordered),
        "population_std_ns": math.sqrt(variance),
    }


def build_runtime_summary(
    *,
    contract: dict[str, Any],
    trials: list[dict[str, Any]],
    environment: dict[str, Any],
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    by_stage = {
        stage_id: [
            next(stage for stage in trial["stages"] if stage["stage_id"] == stage_id)
            for trial in trials
        ]
        for stage_id in RUNTIME_STAGE_IDS
    }
    stages = []
    for stage_id in RUNTIME_STAGE_IDS:
        records = by_stage[stage_id]
        wall = _distribution([int(item["wall_time_ns"]) for item in records])
        cpu = _distribution([int(item["cpu_time_ns"]) for item in records])
        item: dict[str, Any] = {
            "stage_id": stage_id,
            "wall_time_ns": wall,
            "cpu_time_ns": cpu,
            "median_wall_time_ms": wall["median_ns"] / 1_000_000.0,
        }
        if stage_id == "m4-swtpm-esk-sign-probe":
            medians = [
                float(record["outcome"]["median_sign_wall_time_ms"])
                for record in records
            ]
            item["internal_sign_median_ms_across_trials"] = statistics.median(medians)
            item["internal_sign_sample_count"] = sum(
                int(record["outcome"]["measured_sample_count"])
                for record in records
            )
        stages.append(item)
    spans = []
    for span_id in (*SPAN_STAGE_IDS, "measured-total"):
        distribution = _distribution(
            [int(trial["spans"][span_id]) for trial in trials]
        )
        spans.append(
            {
                "span_id": span_id,
                "wall_time_ns": distribution,
                "median_wall_time_ms": distribution["median_ns"] / 1_000_000.0,
            }
        )
    return {
        "schema_version": "1.0",
        "artifact_type": "runtime_overhead_summary",
        "benchmark_id": contract["benchmark_id"],
        "profile": contract["profile"],
        "started_at": started_at,
        "completed_at": completed_at,
        "trial_count": len(trials),
        "stage_count": len(RUNTIME_STAGE_IDS),
        "environment": environment,
        "methodology": {
            "runtime_kind": "containerized-swtpm-prototype",
            "fresh_trust_and_tpm_namespace_per_trial": True,
            "docker_image_build_excluded": True,
            "network_update_api_present": False,
            "submission_transport": "isolated-bind-mounted-directories",
            "physical_tpm_claimed": False,
            "stage_times_additive_within_each_trial": True,
        },
        "stages": stages,
        "spans": spans,
    }


def _samples_document(trials: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "artifact_type": "runtime_overhead_samples",
        "trials": trials,
    }


def build_runtime_manifest(
    *,
    contract: dict[str, Any],
    config_sha256: str,
    source_snapshot_values: list[dict[str, Any]],
    trial_snapshot_values: list[dict[str, Any]],
    samples_bytes: bytes,
    summary_bytes: bytes,
) -> dict[str, Any]:
    core = {
        "schema_version": "1.0",
        "artifact_type": "runtime_overhead_receipt",
        "benchmark_id": contract["benchmark_id"],
        "profile": contract["profile"],
        "config_sha256": config_sha256,
        "implementation_sha256": sha256_file(Path(__file__)),
        "source_snapshots": source_snapshot_values,
        "trial_snapshots": trial_snapshot_values,
        "samples_sha256": sha256_bytes(samples_bytes),
        "summary_sha256": sha256_bytes(summary_bytes),
    }
    return {
        **core,
        "receipt_id": f"runtime-overhead-{digest_object(core)[:24]}",
    }


def create_runtime_overhead_receipt(
    *,
    output: Path,
    config_path: Path,
    trials: list[dict[str, Any]],
    environment: dict[str, Any],
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    contract, config_sha256 = load_runtime_overhead_contract(config_path)
    root = project_root(config_path, contract)
    if output.exists() and any(output.iterdir()):
        raise RuntimeOverheadError(
            f"runtime overhead output must be new or empty: {output}"
        )
    validate_trials(trials, contract, root=root)
    sources = source_snapshots(root=root, contract=contract)
    runtime_snapshots = [
        snapshot
        for trial in trials
        for snapshot in trial_snapshots(trial, root=root)
    ]
    samples_bytes = derived_json_bytes(_samples_document(trials))
    summary = build_runtime_summary(
        contract=contract,
        trials=trials,
        environment=environment,
        started_at=started_at,
        completed_at=completed_at,
    )
    summary_bytes = derived_json_bytes(summary)
    manifest = build_runtime_manifest(
        contract=contract,
        config_sha256=config_sha256,
        source_snapshot_values=sources,
        trial_snapshot_values=runtime_snapshots,
        samples_bytes=samples_bytes,
        summary_bytes=summary_bytes,
    )
    manifest_bytes = canonical_json_bytes(manifest) + b"\n"
    write_once(output / "samples.json", samples_bytes)
    write_once(output / "summary.json", summary_bytes)
    write_once(output / "manifest.json", manifest_bytes)
    return {
        "status": "benchmarked",
        "workspace": str(output),
        "benchmark_id": contract["benchmark_id"],
        "receipt_id": manifest["receipt_id"],
        "trial_count": len(trials),
        "stage_count": len(RUNTIME_STAGE_IDS),
        "manifest_sha256": sha256_file(output / "manifest.json"),
        "span_median_wall_time_ms": {
            item["span_id"]: item["median_wall_time_ms"]
            for item in summary["spans"]
        },
    }


def _load_json_object(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    value = load_json(path)
    if not isinstance(value, dict):
        raise RuntimeOverheadError(f"runtime artifact must be an object: {path.name}")
    return value, raw


def verify_runtime_overhead_receipt(
    *, workspace: Path, config_path: Path
) -> dict[str, Any]:
    errors: list[str] = []
    receipt_id: str | None = None
    benchmark_id: str | None = None
    trial_count = 0
    try:
        contract, config_sha256 = load_runtime_overhead_contract(config_path)
        benchmark_id = contract["benchmark_id"]
        root = project_root(config_path, contract)
        samples_document, samples_raw = _load_json_object(workspace / "samples.json")
        summary, summary_raw = _load_json_object(workspace / "summary.json")
        manifest, manifest_raw = _load_json_object(workspace / "manifest.json")
        if samples_raw != derived_json_bytes(samples_document):
            errors.append("runtime samples.json is not deterministic derived JSON")
        if summary_raw != derived_json_bytes(summary):
            errors.append("runtime summary.json is not deterministic derived JSON")
        if manifest_raw != canonical_json_bytes(manifest) + b"\n":
            errors.append("runtime manifest.json is not canonical")
        trials = samples_document.get("trials")
        if not isinstance(trials, list):
            raise RuntimeOverheadError("runtime samples do not contain a trial list")
        validate_trials(trials, contract, root=root)
        trial_count = len(trials)
        expected_summary = build_runtime_summary(
            contract=contract,
            trials=trials,
            environment=summary.get("environment"),
            started_at=summary.get("started_at"),
            completed_at=summary.get("completed_at"),
        )
        expected_summary_bytes = derived_json_bytes(expected_summary)
        if summary_raw != expected_summary_bytes:
            errors.append("runtime summary statistics or methodology mismatch")
        sources = source_snapshots(root=root, contract=contract)
        runtime_snapshots = [
            snapshot
            for trial in trials
            for snapshot in trial_snapshots(trial, root=root)
        ]
        expected_manifest = build_runtime_manifest(
            contract=contract,
            config_sha256=config_sha256,
            source_snapshot_values=sources,
            trial_snapshot_values=runtime_snapshots,
            samples_bytes=derived_json_bytes(samples_document),
            summary_bytes=expected_summary_bytes,
        )
        if manifest_raw != canonical_json_bytes(expected_manifest) + b"\n":
            errors.append("runtime manifest, source, or trial-evidence binding mismatch")
        receipt_id = manifest.get("receipt_id")
    except (
        FileNotFoundError,
        KeyError,
        OSError,
        RuntimeOverheadError,
        TypeError,
        ValueError,
    ) as exc:
        errors.append(str(exc))
    verified = not errors
    return {
        "status": "verified" if verified else "failed",
        "workspace": str(workspace),
        "benchmark_id": benchmark_id,
        "receipt_id": receipt_id,
        "trial_count": trial_count,
        "stage_count": len(RUNTIME_STAGE_IDS),
        "runtime_evidence_recomputed": verified,
        "source_snapshots_recomputed": verified,
        "statistics_recomputed": verified,
        "implementation_binding_verified": verified,
        "error_count": len(errors),
        "errors": errors,
    }
