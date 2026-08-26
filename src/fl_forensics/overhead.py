"""Auditable warm-process latency benchmarks for verified M4--M8 artifacts.

The benchmark deliberately replays read-only verifiers.  It does not rerun
training, contact a TSA, or claim physical-TPM/runtime latency.  Durations are
derived observations; the receipt binds them to the exact configuration,
implementation, source manifests, and verifier outcomes.
"""

from __future__ import annotations

import math
import os
import platform
import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .attack_mapping import verify_attack_mapping_bundle
from .attestation import verify_attestation_signature
from .campaign_accounting import verify_campaign_accounting
from .canonical import (
    canonical_json_bytes,
    digest_object,
    sha256_bytes,
    sha256_file,
)
from .config import load_yaml
from .crypto import (
    SoftwareECDSASigner,
    load_public_key,
    verify_digest_signature,
)
from .explanation_bundle import verify_explanation_bundle
from .final_preservation import verify_final_preservation
from .investigation_report import verify_investigation_report_bundle
from .merkle import verify_merkle_tree
from .prediction_bundle import verify_prediction_bundle
from .preprocessing import derived_json_bytes
from .preservation import verify_preservation_manifest
from .recovery import verify_recovery_export
from .secure_campaign import verify_secure_campaign
from .storage import load_json, utc_now, write_once
from .timestamp_anchor import verify_timestamp_anchor
from .trust import verify_enrollment_record
from .trust_models import AttestationResultV2, EnrollmentRecord


class OverheadBenchmarkError(ValueError):
    """Raised when the benchmark contract or a measured verifier fails closed."""


Runner = Callable[[dict[str, Path], int], dict[str, Any]]
Marker = tuple[str, str | None]


@dataclass(frozen=True)
class StageDefinition:
    stage_id: str
    scope: str
    required_inputs: tuple[str, ...]
    markers: tuple[Marker, ...]
    runner: Runner


_SOFTWARE_SIGNER: SoftwareECDSASigner | None = None
_MICROBENCHMARK_DIGEST = sha256_bytes(
    b"fl-forensics-overhead-software-ecdsa-p256-sign-verify-v1"
)


def _software_signer() -> SoftwareECDSASigner:
    global _SOFTWARE_SIGNER
    if _SOFTWARE_SIGNER is None:
        _SOFTWARE_SIGNER = SoftwareECDSASigner.generate()
    return _SOFTWARE_SIGNER


def _software_ecdsa_sign_verify(
    _inputs: dict[str, Path], operations: int
) -> dict[str, Any]:
    signer = _software_signer()
    public_key = signer.private_key.public_key()
    for _ in range(operations):
        signature = signer.sign_digest(_MICROBENCHMARK_DIGEST)
        if not signature:
            raise OverheadBenchmarkError("software ECDSA signer returned no signature")
        if not verify_digest_signature(
            public_key, _MICROBENCHMARK_DIGEST, signature
        ):
            raise OverheadBenchmarkError("software ECDSA verification failed")
    return {
        "status": "verified",
        "algorithm": "ECDSA-P256-SHA256",
        "key_backend": "ephemeral-software-memory-only",
        "operation": "sign-and-verify-pair",
        "operation_count": operations,
    }


def _safe_registry_path(value: Any) -> Path:
    path = Path(str(value).replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise OverheadBenchmarkError(f"unsafe M4 registry path: {value}")
    return path


def _verify_m4_attestation_receipts(
    inputs: dict[str, Path], _operations: int
) -> dict[str, Any]:
    """Read-only validation of preserved M4 enrollment and appraisal receipts."""

    workspace = inputs["trust_workspace"]
    manifest = load_json(workspace / "manifest.json")
    index = load_json(workspace / "registry" / "index.json")
    enrollments = index.get("enrollments")
    if not isinstance(enrollments, dict) or not enrollments:
        raise OverheadBenchmarkError("M4 enrollment index is empty")

    enrollment_key = load_public_key(
        (workspace / "authority" / "enrollment-authority.public.pem").read_bytes()
    )
    verifier_key = load_public_key(
        (workspace / "authority" / "attestation-verifier.public.pem").read_bytes()
    )
    expected_clients = sorted(enrollments)
    trust_levels: set[str] = set()
    for client_id, entry in sorted(enrollments.items()):
        record_path = workspace / _safe_registry_path(entry["record_path"])
        record = EnrollmentRecord.model_validate(load_json(record_path))
        if (
            record.core.client_id != client_id
            or record.core.enrollment_id != entry.get("enrollment_id")
            or record.core.status != "active"
            or not verify_enrollment_record(record, enrollment_key)
        ):
            raise OverheadBenchmarkError(
                f"M4 enrollment verification failed: {client_id}"
            )
        trust_levels.add(record.core.trust_level)

    result_paths = sorted((workspace / "results").glob("attestation-*.json"))
    if not result_paths:
        raise OverheadBenchmarkError("M4 attestation result set is empty")
    result_clients: set[str] = set()
    challenge_ids: set[str] = set()
    for path in result_paths:
        result = AttestationResultV2.model_validate(load_json(path))
        if result.result_id != f"attestation-{result.core_digest[:24]}":
            raise OverheadBenchmarkError(
                f"M4 attestation identity mismatch: {path.name}"
            )
        if result.core.status not in {"passed", "passed_with_warning"}:
            raise OverheadBenchmarkError(
                f"M4 attestation did not pass: {result.result_id}"
            )
        entry = enrollments.get(result.core.client_id)
        if entry is None or result.core.enrollment_id != entry.get("enrollment_id"):
            raise OverheadBenchmarkError(
                f"M4 attestation enrollment mismatch: {result.result_id}"
            )
        if not verify_attestation_signature(result, verifier_key):
            raise OverheadBenchmarkError(
                f"M4 attestation signature invalid: {result.result_id}"
            )
        result_clients.add(result.core.client_id)
        challenge_ids.add(result.core.challenge_id)
        trust_levels.add(result.signature.trust_level)
    if sorted(result_clients) != expected_clients:
        raise OverheadBenchmarkError("M4 result set does not cover every enrollment")
    if len(challenge_ids) != len(result_paths):
        raise OverheadBenchmarkError("M4 result set reuses an attestation challenge")
    if int(manifest.get("client_count", -1)) != len(expected_clients):
        raise OverheadBenchmarkError("M4 manifest client count mismatch")
    return {
        "status": "verified",
        "client_count": len(expected_clients),
        "enrollment_count": len(enrollments),
        "attestation_result_count": len(result_paths),
        "unique_challenge_count": len(challenge_ids),
        "trust_levels": sorted(trust_levels),
        "read_only": True,
    }


def _verify_m5(inputs: dict[str, Path], _operations: int) -> dict[str, Any]:
    return verify_secure_campaign(
        workspace=inputs["campaign_workspace"],
        trust_workspace=inputs["trust_workspace"],
        partition_manifest_path=inputs["partition_manifest"],
        server_evaluation_path=inputs["server_evaluation"],
    )


def _verify_m7_predictions(
    inputs: dict[str, Path], _operations: int
) -> dict[str, Any]:
    return verify_prediction_bundle(
        round_workspace=inputs["round_workspace"],
        trust_workspace=inputs["trust_workspace"],
        partition_workspace=inputs["partition_workspace"],
        dataset_workspace=inputs["dataset_workspace"],
        workspace=inputs["prediction_workspace"],
        config_path=inputs["prediction_config"],
    )


def _verify_m7_explanations(
    inputs: dict[str, Path], _operations: int
) -> dict[str, Any]:
    return verify_explanation_bundle(
        round_workspace=inputs["round_workspace"],
        trust_workspace=inputs["trust_workspace"],
        partition_workspace=inputs["partition_workspace"],
        dataset_workspace=inputs["dataset_workspace"],
        prediction_workspace=inputs["prediction_workspace"],
        workspace=inputs["explanation_workspace"],
        prediction_config_path=inputs["prediction_config"],
        config_path=inputs["explanation_config"],
    )


def _verify_m7_attack(inputs: dict[str, Path], _operations: int) -> dict[str, Any]:
    return verify_attack_mapping_bundle(
        round_workspace=inputs["round_workspace"],
        trust_workspace=inputs["trust_workspace"],
        partition_workspace=inputs["partition_workspace"],
        dataset_workspace=inputs["dataset_workspace"],
        prediction_workspace=inputs["prediction_workspace"],
        explanation_workspace=inputs["explanation_workspace"],
        workspace=inputs["attack_workspace"],
        prediction_config_path=inputs["prediction_config"],
        explanation_config_path=inputs["explanation_config"],
        config_path=inputs["attack_config"],
    )


def _verify_m7_report(inputs: dict[str, Path], _operations: int) -> dict[str, Any]:
    return verify_investigation_report_bundle(
        round_workspace=inputs["round_workspace"],
        trust_workspace=inputs["trust_workspace"],
        partition_workspace=inputs["partition_workspace"],
        dataset_workspace=inputs["dataset_workspace"],
        prediction_workspace=inputs["prediction_workspace"],
        explanation_workspace=inputs["explanation_workspace"],
        attack_workspace=inputs["attack_workspace"],
        workspace=inputs["report_workspace"],
        prediction_config_path=inputs["prediction_config"],
        explanation_config_path=inputs["explanation_config"],
        attack_config_path=inputs["attack_config"],
        config_path=inputs["report_config"],
    )


def _verify_m8_preservation(
    inputs: dict[str, Path], _operations: int
) -> dict[str, Any]:
    return verify_preservation_manifest(
        workspace=inputs["preservation_workspace"],
        config_path=inputs["preservation_config"],
    )


def _verify_m8_merkle(inputs: dict[str, Path], _operations: int) -> dict[str, Any]:
    return verify_merkle_tree(
        workspace=inputs["merkle_workspace"],
        config_path=inputs["merkle_config"],
    )


def _verify_m8_timestamp(
    inputs: dict[str, Path], _operations: int
) -> dict[str, Any]:
    return verify_timestamp_anchor(
        workspace=inputs["timestamp_workspace"],
        config_path=inputs["timestamp_config"],
    )


def _verify_m8_recovery(inputs: dict[str, Path], _operations: int) -> dict[str, Any]:
    return verify_recovery_export(workspace=inputs["recovery_workspace"])


def _verify_m8_accounting(
    inputs: dict[str, Path], _operations: int
) -> dict[str, Any]:
    return verify_campaign_accounting(
        workspace=inputs["accounting_workspace"],
        recovery_workspace=inputs["recovery_workspace"],
    )


def _verify_m8_final(inputs: dict[str, Path], _operations: int) -> dict[str, Any]:
    return verify_final_preservation(
        recovery_workspace=inputs["recovery_workspace"],
        accounting_workspace=inputs["accounting_workspace"],
    )


_M7_BASE_INPUTS = (
    "round_workspace",
    "trust_workspace",
    "partition_workspace",
    "dataset_workspace",
    "prediction_workspace",
    "prediction_config",
)
_M7_BASE_MARKERS: tuple[Marker, ...] = (
    ("round_workspace", "checkpoint/manifest.json"),
    ("trust_workspace", "manifest.json"),
    ("partition_workspace", "manifest.json"),
    ("dataset_workspace", "manifest.json"),
    ("prediction_workspace", "manifest.json"),
    ("prediction_config", None),
)


_STAGES = (
    StageDefinition(
        "m4-software-ecdsa-sign-verify",
        "Ephemeral software ECDSA P-256 sign-and-verify pairs; not TPM latency.",
        (),
        (),
        _software_ecdsa_sign_verify,
    ),
    StageDefinition(
        "m4-attestation-receipt-verification",
        "Read-only verification of preserved M4 enrollments and attestation receipts.",
        ("trust_workspace",),
        (
            ("trust_workspace", "manifest.json"),
            ("trust_workspace", "registry/index.json"),
            ("trust_workspace", "authority/enrollment-authority.public.pem"),
            ("trust_workspace", "authority/attestation-verifier.public.pem"),
        ),
        _verify_m4_attestation_receipts,
    ),
    StageDefinition(
        "m5-campaign-verification",
        "Independent verification of the 30-round secure FedAvg campaign.",
        (
            "campaign_workspace",
            "trust_workspace",
            "partition_manifest",
            "server_evaluation",
        ),
        (
            ("campaign_workspace", "campaign-manifest.json"),
            ("trust_workspace", "manifest.json"),
            ("partition_manifest", None),
            ("server_evaluation", None),
        ),
        _verify_m5,
    ),
    StageDefinition(
        "m7-prediction-verification",
        "Prediction and source-lineage recomputation for the six selected cases.",
        _M7_BASE_INPUTS,
        _M7_BASE_MARKERS,
        _verify_m7_predictions,
    ),
    StageDefinition(
        "m7-explanation-verification",
        "Integrated-Gradients and prototype-distance recomputation.",
        _M7_BASE_INPUTS + ("explanation_workspace", "explanation_config"),
        _M7_BASE_MARKERS
        + (
            ("explanation_workspace", "manifest.json"),
            ("explanation_config", None),
        ),
        _verify_m7_explanations,
    ),
    StageDefinition(
        "m7-attack-verification",
        "Versioned ATT&CK hypothesis recomputation.",
        _M7_BASE_INPUTS
        + (
            "explanation_workspace",
            "explanation_config",
            "attack_workspace",
            "attack_config",
        ),
        _M7_BASE_MARKERS
        + (
            ("explanation_workspace", "manifest.json"),
            ("explanation_config", None),
            ("attack_workspace", "manifest.json"),
            ("attack_config", None),
        ),
        _verify_m7_attack,
    ),
    StageDefinition(
        "m7-report-verification",
        "Deterministic investigation-report and source-record recomputation.",
        _M7_BASE_INPUTS
        + (
            "explanation_workspace",
            "explanation_config",
            "attack_workspace",
            "attack_config",
            "report_workspace",
            "report_config",
        ),
        _M7_BASE_MARKERS
        + (
            ("explanation_workspace", "manifest.json"),
            ("explanation_config", None),
            ("attack_workspace", "manifest.json"),
            ("attack_config", None),
            ("report_workspace", "manifest.json"),
            ("report_config", None),
        ),
        _verify_m7_report,
    ),
    StageDefinition(
        "m8-preservation-verification",
        "Reconstruction of the M8 preservation inventory.",
        ("preservation_workspace", "preservation_config"),
        (
            ("preservation_workspace", "manifest.json"),
            ("preservation_workspace", "preservation-manifest.json"),
            ("preservation_config", None),
        ),
        _verify_m8_preservation,
    ),
    StageDefinition(
        "m8-merkle-verification",
        "Reconstruction of the M8 Merkle commitment.",
        ("merkle_workspace", "merkle_config"),
        (
            ("merkle_workspace", "manifest.json"),
            ("merkle_workspace", "merkle-tree.json"),
            ("merkle_config", None),
        ),
        _verify_m8_merkle,
    ),
    StageDefinition(
        "m8-timestamp-verification",
        "Offline RFC 3161 proof verification.",
        ("timestamp_workspace", "timestamp_config"),
        (
            ("timestamp_workspace", "manifest.json"),
            ("timestamp_workspace", "timestamp-proof.json"),
            ("timestamp_workspace", "timestamp-response.tsr"),
            ("timestamp_config", None),
        ),
        _verify_m8_timestamp,
    ),
    StageDefinition(
        "m8-recovery-verification",
        "Offline payload, Merkle, and timestamp verification of the recovery TAR.",
        ("recovery_workspace",),
        (
            ("recovery_workspace", "manifest.json"),
            ("recovery_workspace", "recovery-manifest.json"),
            ("recovery_workspace", "package-inventory.json"),
        ),
        _verify_m8_recovery,
    ),
    StageDefinition(
        "m8-accounting-verification",
        "Recomputation of campaign invariants from the offline recovery package.",
        ("accounting_workspace", "recovery_workspace"),
        (
            ("accounting_workspace", "manifest.json"),
            ("accounting_workspace", "campaign-accounting.json"),
            ("recovery_workspace", "manifest.json"),
        ),
        _verify_m8_accounting,
    ),
    StageDefinition(
        "m8-final-preservation-verification",
        "Fail-closed verification of the complete M8 assurance chain.",
        ("accounting_workspace", "recovery_workspace"),
        (
            ("accounting_workspace", "manifest.json"),
            ("accounting_workspace", "campaign-accounting.json"),
            ("recovery_workspace", "manifest.json"),
            ("recovery_workspace", "recovery-manifest.json"),
            ("recovery_workspace", "package-inventory.json"),
        ),
        _verify_m8_final,
    ),
)
_STAGE_BY_ID = {stage.stage_id: stage for stage in _STAGES}


def load_overhead_contract(config_path: Path) -> tuple[dict[str, Any], str]:
    config, digest = load_yaml(config_path)
    if config.get("schema_version") != "1.0":
        raise OverheadBenchmarkError("unsupported overhead benchmark schema_version")
    if config.get("profile") != "offline-verifier-latency-v1":
        raise OverheadBenchmarkError("overhead benchmark profile mismatch")
    if not str(config.get("benchmark_id", "")).strip():
        raise OverheadBenchmarkError("benchmark_id is required")
    if not isinstance(config.get("project_root"), str):
        raise OverheadBenchmarkError("project_root must be a string")
    inputs = config.get("inputs")
    if not isinstance(inputs, dict):
        raise OverheadBenchmarkError("inputs must be an object")
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in inputs.items()):
        raise OverheadBenchmarkError("input paths must be strings")
    stages = config.get("stages")
    if not isinstance(stages, list) or not stages:
        raise OverheadBenchmarkError("at least one benchmark stage is required")
    ids: list[str] = []
    for item in stages:
        if not isinstance(item, dict):
            raise OverheadBenchmarkError("benchmark stages must be objects")
        stage_id = item.get("stage_id")
        if stage_id not in _STAGE_BY_ID:
            raise OverheadBenchmarkError(f"unknown overhead stage: {stage_id}")
        ids.append(stage_id)
        warmup_runs = item.get("warmup_runs")
        repetitions = item.get("repetitions")
        operations = item.get("operations_per_sample", 1)
        for name, value, minimum, maximum in (
            ("warmup_runs", warmup_runs, 0, 10),
            ("repetitions", repetitions, 1, 100),
            ("operations_per_sample", operations, 1, 100_000),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise OverheadBenchmarkError(
                    f"invalid {name} for overhead stage {stage_id}"
                )
        if stage_id != "m4-software-ecdsa-sign-verify" and operations != 1:
            raise OverheadBenchmarkError(
                f"operations_per_sample must be 1 for end-to-end stage {stage_id}"
            )
        expected = item.get("expected", {"status": "verified"})
        if not isinstance(expected, dict) or expected.get("status") != "verified":
            raise OverheadBenchmarkError(
                f"stage {stage_id} must require status=verified"
            )
        if any(isinstance(value, (dict, list, float)) for value in expected.values()):
            raise OverheadBenchmarkError(
                f"stage assertions must contain scalar integer/string/boolean values: {stage_id}"
            )
        missing = [
            key for key in _STAGE_BY_ID[stage_id].required_inputs if key not in inputs
        ]
        if missing:
            raise OverheadBenchmarkError(
                f"stage {stage_id} is missing inputs: {missing}"
            )
    canonical_order = [stage.stage_id for stage in _STAGES if stage.stage_id in ids]
    if len(ids) != len(set(ids)) or ids != canonical_order:
        raise OverheadBenchmarkError(
            "overhead stages must be unique and follow the canonical M4-to-M8 order"
        )
    return config, digest


def _project_root(config_path: Path, config: dict[str, Any]) -> Path:
    return (config_path.resolve().parent / config["project_root"]).resolve()


def _resolve_input_paths(config: dict[str, Any], root: Path) -> dict[str, Path]:
    resolved: dict[str, Path] = {}
    for key, value in config["inputs"].items():
        raw = Path(value)
        path = (raw if raw.is_absolute() else root / raw).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise OverheadBenchmarkError(
                f"overhead input must remain within the project root: {key}"
            ) from exc
        if not path.exists():
            raise OverheadBenchmarkError(f"overhead input is missing: {key}={value}")
        resolved[key] = path
    return resolved


def _relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def _marker_paths(
    definition: StageDefinition, inputs: dict[str, Path]
) -> list[Path]:
    paths = [
        inputs[key] if suffix is None else inputs[key] / suffix
        for key, suffix in definition.markers
    ]
    if definition.stage_id == "m4-attestation-receipt-verification":
        paths.extend(sorted((inputs["trust_workspace"] / "results").glob("*.json")))
        paths.extend(
            sorted(
                (inputs["trust_workspace"] / "registry" / "enrollments").glob(
                    "*.json"
                )
            )
        )
    unique = sorted(set(paths), key=lambda item: item.as_posix())
    for path in unique:
        if not path.is_file():
            raise OverheadBenchmarkError(f"benchmark source marker is missing: {path}")
        if ".private." in path.name:
            raise OverheadBenchmarkError(
                f"private key cannot be a benchmark source marker: {path.name}"
            )
    return unique


def _source_snapshot(
    definition: StageDefinition, inputs: dict[str, Path], root: Path
) -> dict[str, Any]:
    files = [
        {
            "path": _relative(path, root),
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
        for path in _marker_paths(definition, inputs)
    ]
    core = {"stage_id": definition.stage_id, "files": files}
    return {**core, "snapshot_sha256": digest_object(core)}


def _sanitize(value: Any, root: Path) -> Any:
    if isinstance(value, dict):
        return {str(key): _sanitize(item, root) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize(item, root) for item in value]
    if isinstance(value, tuple):
        return [_sanitize(item, root) for item in value]
    if isinstance(value, Path):
        value = str(value)
    if isinstance(value, str):
        root_text = root.as_posix().rstrip("/")
        normalized = value.replace("\\", "/")
        if normalized == root_text:
            return "."
        if normalized.startswith(root_text + "/"):
            return normalized[len(root_text) + 1 :]
    return value


def _validate_outcome(
    stage: dict[str, Any], result: dict[str, Any]
) -> None:
    if result.get("status") != "verified":
        raise OverheadBenchmarkError(
            f"measured verifier failed for {stage['stage_id']}: {result.get('errors', [])}"
        )
    if int(result.get("error_count", 0)) != 0:
        raise OverheadBenchmarkError(
            f"measured verifier returned errors for {stage['stage_id']}"
        )
    for key, expected in stage.get("expected", {}).items():
        if result.get(key) != expected:
            raise OverheadBenchmarkError(
                f"stage assertion failed for {stage['stage_id']}: "
                f"{key}={result.get(key)!r}, expected {expected!r}"
            )


def _measurement(
    *,
    definition: StageDefinition,
    stage: dict[str, Any],
    inputs: dict[str, Path],
    root: Path,
    snapshot: dict[str, Any],
    sample_index: int,
    warmup: bool,
) -> dict[str, Any]:
    operations = int(stage.get("operations_per_sample", 1))
    wall_start = time.perf_counter_ns()
    cpu_start = time.process_time_ns()
    result = definition.runner(inputs, operations)
    cpu_time_ns = time.process_time_ns() - cpu_start
    wall_time_ns = time.perf_counter_ns() - wall_start
    if not isinstance(result, dict):
        raise OverheadBenchmarkError(
            f"stage did not return a result object: {definition.stage_id}"
        )
    sanitized = _sanitize(result, root)
    _validate_outcome(stage, sanitized)
    after = _source_snapshot(definition, inputs, root)
    if after != snapshot:
        raise OverheadBenchmarkError(
            f"source markers changed while measuring {definition.stage_id}"
        )
    core = {
        "stage_id": definition.stage_id,
        "sample_index": sample_index,
        "warmup": warmup,
        "operation_count": operations,
        "wall_time_ns": wall_time_ns,
        "cpu_time_ns": cpu_time_ns,
        "source_snapshot_sha256": snapshot["snapshot_sha256"],
        "result": sanitized,
    }
    return {
        **core,
        "sample_id": f"overhead-sample-{sha256_bytes(derived_json_bytes(core))[:24]}",
    }


def _describe(values: list[int]) -> dict[str, Any]:
    if not values or any(isinstance(value, bool) or value < 0 for value in values):
        raise OverheadBenchmarkError("timing samples must be non-negative integers")
    ordered = sorted(values)
    count = len(values)
    p95_index = max(0, math.ceil(0.95 * count) - 1)
    return {
        "count": count,
        "mean": statistics.fmean(values),
        "sample_standard_deviation": (
            statistics.stdev(values) if count > 1 else None
        ),
        "minimum": min(values),
        "median": statistics.median(values),
        "p95_nearest_rank": ordered[p95_index],
        "maximum": max(values),
    }


def _milliseconds(value: float) -> float:
    return float(value) / 1_000_000.0


def _stage_summary(
    definition: StageDefinition,
    stage: dict[str, Any],
    samples: list[dict[str, Any]],
) -> dict[str, Any]:
    measured = [item for item in samples if not item["warmup"]]
    wall = [int(item["wall_time_ns"]) for item in measured]
    cpu = [int(item["cpu_time_ns"]) for item in measured]
    operations = int(stage.get("operations_per_sample", 1))
    wall_stats = _describe(wall)
    cpu_stats = _describe(cpu)
    return {
        "stage_id": definition.stage_id,
        "scope": definition.scope,
        "warmup_runs": int(stage["warmup_runs"]),
        "repetitions": int(stage["repetitions"]),
        "operations_per_sample": operations,
        "source_snapshot_sha256": measured[0]["source_snapshot_sha256"],
        "wall_time_ns": wall_stats,
        "cpu_time_ns": cpu_stats,
        "median_wall_time_ms": _milliseconds(wall_stats["median"]),
        "mean_wall_time_ms": _milliseconds(wall_stats["mean"]),
        "p95_wall_time_ms": _milliseconds(wall_stats["p95_nearest_rank"]),
        "mean_wall_time_microseconds_per_operation": (
            float(wall_stats["mean"]) / operations / 1_000.0
        ),
        "verified_result": measured[-1]["result"],
    }


def _environment() -> dict[str, Any]:
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "operating_system": platform.system(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "clock": "time.perf_counter_ns",
        "cpu_clock": "time.process_time_ns",
        "process_model": "warm-in-process-sequential",
    }


def _build_summary(
    *,
    contract: dict[str, Any],
    samples: list[dict[str, Any]],
    snapshots: list[dict[str, Any]],
    environment: dict[str, Any],
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    by_stage = {
        stage["stage_id"]: [
            sample for sample in samples if sample["stage_id"] == stage["stage_id"]
        ]
        for stage in contract["stages"]
    }
    summaries = [
        _stage_summary(_STAGE_BY_ID[stage["stage_id"]], stage, by_stage[stage["stage_id"]])
        for stage in contract["stages"]
    ]
    measured = [sample for sample in samples if not sample["warmup"]]
    return {
        "schema_version": "1.0",
        "artifact_type": "m4_m8_offline_overhead_summary",
        "benchmark_id": contract["benchmark_id"],
        "profile": contract["profile"],
        "started_at": started_at,
        "completed_at": completed_at,
        "environment": environment,
        "stage_count": len(contract["stages"]),
        "measured_sample_count": len(measured),
        "warmup_sample_count": len(samples) - len(measured),
        "total_measured_wall_time_ns": sum(
            int(sample["wall_time_ns"]) for sample in measured
        ),
        "source_snapshot_count": len(snapshots),
        "stages": summaries,
        "interpretation_constraints": [
            "Measurements are sequential warm-process verifier latency; Python startup is excluded.",
            "The benchmark replays existing artifacts and does not rerun training or create evidence.",
            "The software ECDSA microbenchmark is not a swtpm or physical-TPM latency claim.",
            "M4 receipt verification checks preserved signed appraisal results, not a live Quote exchange.",
            "Filesystem cache state, host load, and virtualization can influence observed durations.",
            "The receipt proves internal integrity, not the honesty of the host clock; preserve or externally anchor it for retention.",
        ],
    }


def _samples_document(samples: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "artifact_type": "m4_m8_offline_overhead_samples",
        "samples": samples,
    }


def _build_manifest(
    *,
    contract: dict[str, Any],
    config_sha256: str,
    snapshots: list[dict[str, Any]],
    samples_bytes: bytes,
    summary_bytes: bytes,
) -> dict[str, Any]:
    core = {
        "schema_version": "1.0",
        "artifact_type": "m4_m8_offline_overhead_manifest",
        "benchmark_id": contract["benchmark_id"],
        "profile": contract["profile"],
        "config_sha256": config_sha256,
        "implementation_sha256": sha256_file(Path(__file__)),
        "samples_sha256": sha256_bytes(samples_bytes),
        "summary_sha256": sha256_bytes(summary_bytes),
        "source_snapshots": snapshots,
        "stages": [
            {
                "stage_id": stage["stage_id"],
                "warmup_runs": stage["warmup_runs"],
                "repetitions": stage["repetitions"],
                "operations_per_sample": stage.get("operations_per_sample", 1),
                "expected": stage.get("expected", {"status": "verified"}),
            }
            for stage in contract["stages"]
        ],
    }
    return {
        **core,
        "receipt_id": f"overhead-benchmark-{digest_object(core)[:24]}",
    }


def _validate_samples(
    samples: list[dict[str, Any]], contract: dict[str, Any]
) -> None:
    expected_total = 0
    for stage in contract["stages"]:
        stage_id = stage["stage_id"]
        selected = [item for item in samples if item.get("stage_id") == stage_id]
        total = int(stage["warmup_runs"]) + int(stage["repetitions"])
        expected_total += total
        if len(selected) != total:
            raise OverheadBenchmarkError(f"sample count mismatch: {stage_id}")
        for index, sample in enumerate(selected):
            expected_warmup = index < int(stage["warmup_runs"])
            if sample.get("sample_index") != index or sample.get("warmup") is not expected_warmup:
                raise OverheadBenchmarkError(f"sample sequence mismatch: {stage_id}")
            operations = int(stage.get("operations_per_sample", 1))
            if sample.get("operation_count") != operations:
                raise OverheadBenchmarkError(f"operation count mismatch: {stage_id}")
            for key in ("wall_time_ns", "cpu_time_ns"):
                value = sample.get(key)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise OverheadBenchmarkError(f"invalid {key}: {stage_id}")
            result = sample.get("result")
            if not isinstance(result, dict):
                raise OverheadBenchmarkError(f"missing verifier result: {stage_id}")
            _validate_outcome(stage, result)
            core = {key: value for key, value in sample.items() if key != "sample_id"}
            expected_id = f"overhead-sample-{sha256_bytes(derived_json_bytes(core))[:24]}"
            if sample.get("sample_id") != expected_id:
                raise OverheadBenchmarkError(f"sample identity mismatch: {stage_id}")
    if len(samples) != expected_total:
        raise OverheadBenchmarkError("unexpected samples are present")


def create_overhead_benchmark(
    *,
    output: Path,
    config_path: Path,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    contract, config_sha256 = load_overhead_contract(config_path)
    root = _project_root(config_path, contract)
    inputs = _resolve_input_paths(contract, root)
    if output.exists() and any(output.iterdir()):
        raise OverheadBenchmarkError(
            f"overhead benchmark output must be new or empty: {output}"
        )
    if any(
        stage["stage_id"] == "m4-software-ecdsa-sign-verify"
        for stage in contract["stages"]
    ):
        _software_signer()
    started_at = utc_now()
    environment = _environment()
    samples: list[dict[str, Any]] = []
    snapshots: list[dict[str, Any]] = []
    for stage in contract["stages"]:
        definition = _STAGE_BY_ID[stage["stage_id"]]
        if progress is not None:
            progress(
                f"[overhead] starting {definition.stage_id} "
                f"(warmup={stage['warmup_runs']}, repetitions={stage['repetitions']})"
            )
        snapshot = _source_snapshot(definition, inputs, root)
        snapshots.append(snapshot)
        total = int(stage["warmup_runs"]) + int(stage["repetitions"])
        for index in range(total):
            samples.append(
                _measurement(
                    definition=definition,
                    stage=stage,
                    inputs=inputs,
                    root=root,
                    snapshot=snapshot,
                    sample_index=index,
                    warmup=index < int(stage["warmup_runs"]),
                )
            )
        if progress is not None:
            progress(f"[overhead] completed {definition.stage_id}")
    completed_at = utc_now()
    _validate_samples(samples, contract)
    summary = _build_summary(
        contract=contract,
        samples=samples,
        snapshots=snapshots,
        environment=environment,
        started_at=started_at,
        completed_at=completed_at,
    )
    samples_bytes = derived_json_bytes(_samples_document(samples))
    summary_bytes = derived_json_bytes(summary)
    manifest = _build_manifest(
        contract=contract,
        config_sha256=config_sha256,
        snapshots=snapshots,
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
        "stage_count": summary["stage_count"],
        "measured_sample_count": summary["measured_sample_count"],
        "total_measured_wall_time_seconds": (
            summary["total_measured_wall_time_ns"] / 1_000_000_000.0
        ),
        "stage_median_wall_time_ms": {
            item["stage_id"]: item["median_wall_time_ms"]
            for item in summary["stages"]
        },
        "manifest_sha256": sha256_file(output / "manifest.json"),
    }


def _load_json_object(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    import json

    value = json.loads(raw)
    if not isinstance(value, dict):
        raise OverheadBenchmarkError(f"benchmark artifact must be an object: {path.name}")
    return value, raw


def verify_overhead_benchmark(
    *, workspace: Path, config_path: Path
) -> dict[str, Any]:
    errors: list[str] = []
    receipt_id: str | None = None
    benchmark_id: str | None = None
    stage_count = 0
    sample_count = 0
    try:
        contract, config_sha256 = load_overhead_contract(config_path)
        benchmark_id = contract["benchmark_id"]
        root = _project_root(config_path, contract)
        inputs = _resolve_input_paths(contract, root)
        samples_document, samples_raw = _load_json_object(workspace / "samples.json")
        summary, summary_raw = _load_json_object(workspace / "summary.json")
        manifest, manifest_raw = _load_json_object(workspace / "manifest.json")
        if samples_raw != derived_json_bytes(samples_document):
            errors.append("samples.json is not in deterministic derived-JSON form")
        if summary_raw != derived_json_bytes(summary):
            errors.append("summary.json is not in deterministic derived-JSON form")
        if manifest_raw != canonical_json_bytes(manifest) + b"\n":
            errors.append("manifest.json is not canonical")
        samples = samples_document.get("samples")
        if not isinstance(samples, list):
            raise OverheadBenchmarkError("samples.json does not contain a sample list")
        _validate_samples(samples, contract)
        snapshots = [
            _source_snapshot(_STAGE_BY_ID[stage["stage_id"]], inputs, root)
            for stage in contract["stages"]
        ]
        expected_summary = _build_summary(
            contract=contract,
            samples=samples,
            snapshots=snapshots,
            environment=summary.get("environment"),
            started_at=summary.get("started_at"),
            completed_at=summary.get("completed_at"),
        )
        expected_summary_bytes = derived_json_bytes(expected_summary)
        if summary_raw != expected_summary_bytes:
            errors.append("overhead summary statistics or metadata mismatch")
        expected_manifest = _build_manifest(
            contract=contract,
            config_sha256=config_sha256,
            snapshots=snapshots,
            samples_bytes=derived_json_bytes(samples_document),
            summary_bytes=expected_summary_bytes,
        )
        expected_manifest_bytes = canonical_json_bytes(expected_manifest) + b"\n"
        if manifest_raw != expected_manifest_bytes:
            errors.append("overhead manifest, source binding, or implementation mismatch")
        receipt_id = manifest.get("receipt_id")
        stage_count = len(contract["stages"])
        sample_count = sum(not item["warmup"] for item in samples)
    except (
        FileNotFoundError,
        KeyError,
        OSError,
        OverheadBenchmarkError,
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
        "stage_count": stage_count,
        "measured_sample_count": sample_count,
        "source_snapshots_recomputed": verified,
        "statistics_recomputed": verified,
        "implementation_binding_verified": verified,
        "error_count": len(errors),
        "errors": errors,
    }
