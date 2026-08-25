"""M8.1 deterministic preservation-manifest creation and verification."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

from .attestation import verify_attestation_signature
from .canonical import canonical_json_bytes, digest_object, sha256_bytes, sha256_file
from .config import load_yaml
from .crypto import load_public_key, public_key_id, verify_digest_signature
from .investigation_models import PredictionBundleManifest
from .investigation_report import verify_investigation_report_bundle
from .preservation_models import (
    PRESERVATION_PROFILE,
    ExcludedMaterial,
    ExternalEvidenceBinding,
    PreservationCore,
    PreservationEnvelope,
    PreservationManifest,
    PreservationState,
    PreservedArtifact,
)
from .secure_campaign import verify_secure_campaign
from .storage import load_json, write_json_once
from .trust import verify_enrollment_record
from .trust_models import AttestationChallenge, AttestationResultV2, EnrollmentRecord


class PreservationError(ValueError):
    """Raised when the preservation boundary cannot be proven."""


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _settings(config_path: Path) -> tuple[Path, dict[str, Any], str]:
    value, digest = load_yaml(config_path)
    settings = value.get("preservation")
    if not isinstance(settings, dict):
        raise PreservationError("missing preservation configuration")
    return config_path.resolve().parent.parent, settings, digest


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise PreservationError(f"artifact is outside project root: {path}") from exc


def _artifact(
    *,
    path: Path,
    root: Path,
    artifact_role: str,
    milestone: str,
    workspace_role: str,
    preservation_class: str,
    dependencies: list[str] | None = None,
    verification: dict[str, Any] | None = None,
    campaign_references: list[str] | None = None,
) -> PreservedArtifact:
    if not path.is_file():
        raise PreservationError(f"required artifact is missing: {path}")
    relative_path = _safe_relative(path, root)
    descriptor = {
        "relative_path": relative_path,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "artifact_role": artifact_role,
        "milestone": milestone,
        "workspace_role": workspace_role,
        "preservation_class": preservation_class,
    }
    return PreservedArtifact(
        artifact_id=f"preserved-artifact-{digest_object(descriptor)[:24]}",
        **descriptor,
        upstream_dependencies=dependencies or [],
        source_verification=verification or {},
        campaign_references=campaign_references or [],
    )


def _files(path: Path) -> list[Path]:
    if not path.is_dir():
        raise PreservationError(f"required workspace is missing: {path}")
    return sorted(item for item in path.rglob("*") if item.is_file())


def _excluded(relative: str, patterns: list[str]) -> bool:
    return any(
        fnmatch.fnmatch(relative, pattern)
        or fnmatch.fnmatch(Path(relative).name, pattern)
        for pattern in patterns
    )


def _verify_challenge(challenge: AttestationChallenge, public_key: Any) -> bool:
    digest = digest_object(challenge.core.model_dump(mode="json"))
    return (
        digest == challenge.core_digest
        and challenge.signature.key_id == public_key_id(public_key)
        and verify_digest_signature(
            public_key, challenge.core_digest, challenge.signature.value_b64
        )
    )


def _trust_boundary(
    *, root: Path, trust: Path, campaign: Path, policy_context: list[str]
) -> list[PreservedArtifact]:
    enrollment_key_path = trust / "authority/enrollment-authority.public.pem"
    attestation_key_path = trust / "authority/attestation-verifier.public.pem"
    enrollment_key = load_public_key(enrollment_key_path.read_bytes())
    attestation_key = load_public_key(attestation_key_path.read_bytes())
    index_path = trust / "registry/index.json"
    index = load_json(index_path)
    attestation_refs: dict[str, str] = {}
    enrollment_ids: set[str] = set()
    challenge_ids: set[str] = set()

    for bundle_path in sorted(campaign.glob("rounds/round-*/submissions/*/bundle.json")):
        bundle = load_json(bundle_path)
        core = bundle["core"]
        result_id = str(core["attestation_result_id"])
        result_digest = str(core["attestation_result_sha256"])
        previous = attestation_refs.setdefault(result_id, result_digest)
        if previous != result_digest:
            raise PreservationError(f"conflicting M5 attestation digest: {result_id}")
    if not attestation_refs:
        raise PreservationError("M5 campaign references no attestations")

    artifacts = [
        _artifact(
            path=index_path,
            root=root,
            artifact_role="enrollment-registry-index",
            milestone="M4",
            workspace_role="trust-assurance",
            preservation_class="referenced-trust-registry",
        ),
        _artifact(
            path=enrollment_key_path,
            root=root,
            artifact_role="enrollment-authority-public-key",
            milestone="M4",
            workspace_role="trust-assurance",
            preservation_class="public-verification-material",
        ),
        _artifact(
            path=attestation_key_path,
            root=root,
            artifact_role="attestation-verifier-public-key",
            milestone="M4",
            workspace_role="trust-assurance",
            preservation_class="public-verification-material",
        ),
    ]
    for result_id, expected_sha256 in sorted(attestation_refs.items()):
        path = trust / "results" / f"{result_id}.json"
        if sha256_file(path) != expected_sha256:
            raise PreservationError(f"M5 attestation digest mismatch: {result_id}")
        result = AttestationResultV2.model_validate(load_json(path))
        if result.result_id != result_id or not verify_attestation_signature(
            result, attestation_key
        ):
            raise PreservationError(f"invalid referenced attestation: {result_id}")
        enrollment_ids.add(result.core.enrollment_id)
        challenge_ids.add(result.core.challenge_id)
        artifacts.append(
            _artifact(
                path=path,
                root=root,
                artifact_role="referenced-attestation-result",
                milestone="M4",
                workspace_role="trust-assurance",
                preservation_class="campaign-referenced-trust-artifact",
                verification={"m5_sha256_match": True, "signature_verified": True},
                campaign_references=[result_id],
            )
        )

    enrollment_by_id: dict[str, Path] = {}
    for client_id, entry in sorted(index.get("enrollments", {}).items()):
        path = trust / Path(str(entry["record_path"]).replace("\\", "/"))
        record = EnrollmentRecord.model_validate(load_json(path))
        if not verify_enrollment_record(record, enrollment_key):
            raise PreservationError(f"invalid enrollment: {client_id}")
        if entry.get("enrollment_id") != record.core.enrollment_id:
            raise PreservationError(f"enrollment index identity mismatch: {client_id}")
        if entry.get("record_digest") != digest_object(
            record.model_dump(mode="json")
        ):
            raise PreservationError(f"enrollment index digest mismatch: {client_id}")
        enrollment_by_id[record.core.enrollment_id] = path
    if set(enrollment_by_id) != enrollment_ids:
        raise PreservationError("M4 enrollment set differs from M5 references")
    for enrollment_id, path in sorted(enrollment_by_id.items()):
        artifacts.append(
            _artifact(
                path=path,
                root=root,
                artifact_role="referenced-enrollment-record",
                milestone="M4",
                workspace_role="trust-assurance",
                preservation_class="campaign-referenced-trust-artifact",
                verification={"authority_signature_verified": True},
                campaign_references=[enrollment_id],
            )
        )

    for challenge_id in sorted(challenge_ids):
        path = trust / "challenges" / f"{challenge_id}.json"
        challenge = AttestationChallenge.model_validate(load_json(path))
        if challenge.core.challenge_id != challenge_id or not _verify_challenge(
            challenge, attestation_key
        ):
            raise PreservationError(f"invalid referenced challenge: {challenge_id}")
        if challenge.core.enrollment_id not in enrollment_ids:
            raise PreservationError(f"challenge enrollment is outside boundary: {challenge_id}")
        artifacts.append(
            _artifact(
                path=path,
                root=root,
                artifact_role="referenced-attestation-challenge",
                milestone="M4",
                workspace_role="trust-assurance",
                preservation_class="campaign-referenced-trust-artifact",
                verification={"verifier_signature_verified": True},
                campaign_references=[challenge_id],
            )
        )

    revocations = trust / "registry/revocations"
    for path in _files(revocations) if revocations.is_dir() else []:
        artifacts.append(
            _artifact(
                path=path,
                root=root,
                artifact_role="revocation-record",
                milestone="M4",
                workspace_role="trust-assurance",
                preservation_class="revocation-snapshot",
            )
        )
    for relative in policy_context:
        artifacts.append(
            _artifact(
                path=trust / relative,
                root=root,
                artifact_role="trust-policy-context",
                milestone="M4",
                workspace_role="trust-assurance",
                preservation_class="public-trust-context",
            )
        )
    return sorted(artifacts, key=lambda item: item.relative_path)


def _verify_sources(root: Path, settings: dict[str, Any]) -> None:
    campaign = _resolve(root, settings["campaign_workspace"])
    trust = _resolve(root, settings["trust_workspace"])
    campaign_result = verify_secure_campaign(
        workspace=campaign,
        trust_workspace=trust,
        partition_manifest_path=_resolve(root, settings["partition_manifest"]),
        server_evaluation_path=_resolve(root, settings["server_evaluation"]),
    )
    if campaign_result.get("status") != "verified":
        raise PreservationError(
            f"M5 campaign verification failed: {campaign_result.get('errors', [])}"
        )
    selected = int(campaign_result["selected_round"])
    if selected != int(settings["selected_derivation_round"]):
        raise PreservationError("configured selected round differs from verified campaign")
    report_result = verify_investigation_report_bundle(
        round_workspace=campaign / "rounds" / f"round-{selected:03d}",
        trust_workspace=trust,
        partition_workspace=_resolve(root, settings["partition_workspace"]),
        dataset_workspace=_resolve(root, settings["dataset_workspace"]),
        prediction_workspace=_resolve(root, settings["prediction_workspace"]),
        explanation_workspace=_resolve(root, settings["explanation_workspace"]),
        attack_workspace=_resolve(root, settings["attack_workspace"]),
        workspace=_resolve(root, settings["report_workspace"]),
        prediction_config_path=_resolve(root, settings["prediction_config"]),
        explanation_config_path=_resolve(root, settings["explanation_config"]),
        attack_config_path=_resolve(root, settings["attack_config"]),
        config_path=_resolve(root, settings["report_config"]),
    )
    if report_result.get("status") != "verified":
        raise PreservationError(
            f"M7 report verification failed: {report_result.get('errors', [])}"
        )
    prediction = PredictionBundleManifest.model_validate(
        load_json(_resolve(root, settings["prediction_workspace"]) / "manifest.json")
    )
    if prediction.core.sources.round_number != selected:
        raise PreservationError("M7 prediction does not reference the selected M5 round")


def _build_core(root: Path, settings: dict[str, Any]) -> PreservationCore:
    expected_rounds = int(settings["expected_rounds"])
    campaign = _resolve(root, settings["campaign_workspace"])
    round_names = sorted(path.name for path in (campaign / "rounds").iterdir() if path.is_dir())
    expected_names = [f"round-{number:03d}" for number in range(1, expected_rounds + 1)]
    if round_names != expected_names:
        raise PreservationError("campaign round directories differ from the expected set")
    patterns = [str(item) for item in settings["excluded_patterns"]]
    derivation: list[PreservedArtifact] = []
    dataset = _resolve(root, settings["dataset_workspace"])
    expected_m2 = sorted(str(item) for item in settings["required_m2_files"])
    actual_m2 = sorted(path.relative_to(dataset).as_posix() for path in _files(dataset))
    if actual_m2 != expected_m2:
        raise PreservationError("M2 artifact set differs from the required boundary")
    groups = [
        (dataset, "M2", "primary-evidence-derivation"),
        (_resolve(root, settings["partition_workspace"]), "M3", "federated-data-derivation"),
        (_resolve(root, settings["prediction_workspace"]), "M7.1", "model-measurement"),
        (_resolve(root, settings["explanation_workspace"]), "M7.2", "derived-interpretation"),
        (_resolve(root, settings["attack_workspace"]), "M7.3", "derived-interpretation"),
        (_resolve(root, settings["report_workspace"]), "M7.4", "investigation-report"),
    ]
    for workspace, milestone, role in groups:
        for path in _files(workspace):
            derivation.append(
                _artifact(
                    path=path,
                    root=root,
                    artifact_role=role,
                    milestone=milestone,
                    workspace_role="derivation-chain",
                    preservation_class="required-causal-artifact",
                )
            )
    for name in ("prediction_config", "explanation_config", "attack_config", "report_config"):
        derivation.append(
            _artifact(
                path=_resolve(root, settings[name]),
                root=root,
                artifact_role="recomputation-configuration",
                milestone="M7",
                workspace_role="derivation-chain",
                preservation_class="recomputation-dependency",
            )
        )

    campaign_artifacts: list[PreservedArtifact] = []
    for path in _files(campaign):
        relative = path.relative_to(campaign).as_posix()
        if _excluded(relative, patterns):
            continue
        campaign_artifacts.append(
            _artifact(
                path=path,
                root=root,
                artifact_role=(
                    "selected-derivation-round"
                    if relative.startswith(
                        f"rounds/round-{int(settings['selected_derivation_round']):03d}/"
                    )
                    else "campaign-assurance"
                ),
                milestone="M5",
                workspace_role="campaign-assurance",
                preservation_class="complete-secure-campaign",
                campaign_references=[relative.split("/")[1]]
                if relative.startswith("rounds/")
                else [],
            )
        )
    trust_artifacts = _trust_boundary(
        root=root,
        trust=_resolve(root, settings["trust_workspace"]),
        campaign=campaign,
        policy_context=[str(item) for item in settings["trust_policy_context"]],
    )
    all_artifacts = derivation + trust_artifacts + campaign_artifacts
    if any(_excluded(item.relative_path, patterns) for item in all_artifacts):
        raise PreservationError("excluded material entered the preservation inventory")
    paths = [item.relative_path for item in all_artifacts]
    if len(paths) != len(set(paths)):
        raise PreservationError("preservation inventory contains duplicate paths")
    inventory = [item.model_dump(mode="json") for item in sorted(all_artifacts, key=lambda x: x.relative_path)]
    m2_manifest = load_json(dataset / "manifest.json")
    external = [
        ExternalEvidenceBinding(
            relative_path=str(item["relative_path"]),
            sha256=str(item["sha256"]),
            size_bytes=int(item["size_bytes"]),
            binding_source=_safe_relative(dataset / "manifest.json", root),
        )
        for item in sorted(m2_manifest.get("source_files", []), key=lambda x: x["relative_path"])
    ]
    if not external:
        raise PreservationError("M2 manifest contains no external-evidence bindings")
    return PreservationCore(
        profile=PRESERVATION_PROFILE,
        derivation_chain=sorted(derivation, key=lambda item: item.relative_path),
        trust_assurance=trust_artifacts,
        campaign_assurance=sorted(campaign_artifacts, key=lambda item: item.relative_path),
        external_evidence=external,
        excluded_material=[
            ExcludedMaterial(
                pattern=pattern,
                reason=(
                    "private-cryptographic-material"
                    if "private" in pattern
                    else "mutable-runtime-state"
                ),
            )
            for pattern in patterns
        ],
        selected_derivation_round=int(settings["selected_derivation_round"]),
        campaign_rounds=list(range(1, expected_rounds + 1)),
        preservation_state=PreservationState(
            artifact_count=len(inventory),
            total_size_bytes=sum(item["size_bytes"] for item in inventory),
            inventory_sha256=sha256_bytes(canonical_json_bytes(inventory)),
        ),
    )


def _artifacts(core: PreservationCore) -> list[PreservedArtifact]:
    return core.derivation_chain + core.trust_assurance + core.campaign_assurance


def create_preservation_manifest(
    *, output: Path, config_path: Path, verify_sources: bool = True
) -> dict[str, Any]:
    root, settings, config_sha256 = _settings(config_path)
    if verify_sources:
        _verify_sources(root, settings)
    core = _build_core(root, settings)
    core_digest = digest_object(core.model_dump(mode="json"))
    manifest = PreservationManifest(
        preservation_id=f"m8-preservation-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
    )
    manifest_bytes = canonical_json_bytes(manifest.model_dump(mode="json")) + b"\n"
    envelope = PreservationEnvelope(
        preservation_id=manifest.preservation_id,
        preservation_manifest_sha256=sha256_bytes(manifest_bytes),
        canonical_core_sha256=core_digest,
        implementation_sha256=sha256_file(Path(__file__)),
        config_sha256=config_sha256,
        preservation_state=PRESERVATION_PROFILE,
    )
    write_json_once(output / "preservation-manifest.json", manifest.model_dump(mode="json"))
    write_json_once(output / "manifest.json", envelope.model_dump(mode="json"))
    return {
        "status": "preserved",
        "preservation_id": manifest.preservation_id,
        "artifact_count": core.preservation_state.artifact_count,
        "trust_attestation_count": sum(
            item.artifact_role == "referenced-attestation-result"
            for item in core.trust_assurance
        ),
        "campaign_round_count": len(core.campaign_rounds),
        "workspace": str(output),
    }


def verify_preservation_manifest(
    *, workspace: Path, config_path: Path, verify_sources: bool = True
) -> dict[str, Any]:
    errors: list[str] = []
    manifest: PreservationManifest | None = None
    try:
        names = sorted(path.relative_to(workspace).as_posix() for path in _files(workspace))
        if names != ["manifest.json", "preservation-manifest.json"]:
            raise PreservationError("unexpected M8.1 workspace artifact set")
        manifest_path = workspace / "preservation-manifest.json"
        envelope_path = workspace / "manifest.json"
        manifest = PreservationManifest.model_validate(load_json(manifest_path))
        PreservationEnvelope.model_validate(load_json(envelope_path))
        root, settings, config_sha256 = _settings(config_path)
        if verify_sources:
            _verify_sources(root, settings)
        expected_core = _build_core(root, settings)
        expected_digest = digest_object(expected_core.model_dump(mode="json"))
        expected_id = f"m8-preservation-{expected_digest[:24]}"
        expected_manifest = PreservationManifest(
            preservation_id=expected_id,
            core=expected_core,
            canonical_core_sha256=expected_digest,
        )
        expected_bytes = canonical_json_bytes(expected_manifest.model_dump(mode="json")) + b"\n"
        expected_envelope = PreservationEnvelope(
            preservation_id=expected_id,
            preservation_manifest_sha256=sha256_bytes(expected_bytes),
            canonical_core_sha256=expected_digest,
            implementation_sha256=sha256_file(Path(__file__)),
            config_sha256=config_sha256,
            preservation_state=PRESERVATION_PROFILE,
        )
        if manifest_path.read_bytes() != expected_bytes:
            errors.append("preservation manifest differs from reconstructed inventory")
        if envelope_path.read_bytes() != (
            canonical_json_bytes(expected_envelope.model_dump(mode="json")) + b"\n"
        ):
            errors.append("preservation envelope differs from reconstruction")
        for artifact in _artifacts(manifest.core):
            path = root / artifact.relative_path
            if not path.is_file() or sha256_file(path) != artifact.sha256:
                errors.append(f"preserved artifact mismatch: {artifact.relative_path}")
    except (KeyError, OSError, PreservationError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "preservation_id": manifest.preservation_id if manifest else None,
        "artifact_count": manifest.core.preservation_state.artifact_count if manifest else 0,
        "inventory_reconstructed": not errors,
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }
