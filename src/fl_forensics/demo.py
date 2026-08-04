"""Executable phase-1 demonstration."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import __version__
from .acquisition import build_batch
from .admission import AdmissionController
from .attestation import create_development_attestation
from .canonical import digest_object, sha256_bytes
from .config import load_yaml
from .crypto import SoftwareECDSASigner, load_public_key
from .lineage import LineageStore
from .models import IdentityRecord
from .snapshot import build_snapshot
from .storage import atomic_write, utc_now, write_json_once
from .vault import EvidenceVault


def _save_signer(directory: Path, name: str, signer: SoftwareECDSASigner) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / f"{name}.private.pem"
    public_path = directory / f"{name}.public.pem"
    atomic_write(private_path, signer.private_pem())
    private_path.chmod(0o600)
    atomic_write(public_path, signer.public_pem())


def run_demo(*, input_path: Path, output: Path, config_path: Path) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"demo output must be empty or absent: {output}")
    output.mkdir(parents=True, exist_ok=True)
    config, config_digest = load_yaml(config_path)
    input_digest = sha256_bytes(input_path.read_bytes())
    experiment_core = {
        "schema_version": "1.0",
        "name": "phase-1-evidence-vertical-slice",
        "input_digest": input_digest,
        "configuration_digest": config_digest,
        "software_version": __version__,
        "seed": int(config["experiment"]["seed"]),
    }
    experiment_id = f"experiment-{digest_object(experiment_core)[:24]}"

    keys_directory = output / "operational" / "keys"
    evidence_signer = SoftwareECDSASigner.generate()
    verifier_signer = SoftwareECDSASigner.generate()
    repository_signer = SoftwareECDSASigner.generate()
    _save_signer(keys_directory, "client01-evidence", evidence_signer)
    _save_signer(keys_directory, "attestation-verifier", verifier_signer)
    _save_signer(keys_directory, "repository", repository_signer)

    now = datetime.now(UTC)
    identity = IdentityRecord(
        client_id="client01",
        node_id="node01",
        evidence_key_id=evidence_signer.key_id,
        evidence_public_key_pem=evidence_signer.public_pem().decode("utf-8"),
        status="active",
        valid_from=(now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        valid_until=(now + timedelta(days=365)).isoformat().replace("+00:00", "Z"),
    )
    registry = {
        "schema_version": "1.0",
        "identities": [identity.model_dump(mode="json")],
        "verifier_key_id": verifier_signer.key_id,
        "verifier_public_key_pem": verifier_signer.public_pem().decode("utf-8"),
        "repository_key_id": repository_signer.key_id,
        "repository_public_key_pem": repository_signer.public_pem().decode("utf-8"),
    }
    write_json_once(output / "registry" / "identity_registry.json", registry)

    attestation = create_development_attestation(
        node_id="node01",
        client_id="client01",
        signer=verifier_signer,
        quote_digest=sha256_bytes(b"phase-1-no-tpm-quote"),
        measurement_log_digest=sha256_bytes(b"phase-1-no-pcr-or-ima-appraisal"),
        nonce=secrets.token_hex(32),
    )
    attestation_path = output / "trust" / f"{attestation.result_id}.json"
    write_json_once(attestation_path, attestation.model_dump(mode="json"))

    built_batch = build_batch(
        input_path=input_path,
        queue_root=output / "client01" / "queue",
        node_id="node01",
        client_id="client01",
        session_id=experiment_id,
        sequence_number=0,
        attestation=attestation,
        signer=evidence_signer,
        configuration_digest=config_digest,
    )

    vault = EvidenceVault(output / "vault")
    controller = AdmissionController(
        identities={"client01": identity},
        verifier_public_key=load_public_key(verifier_signer.public_pem()),
        repository_signer=repository_signer,
        vault=vault,
    )
    outcome = controller.process(
        raw=built_batch.raw,
        manifest=built_batch.manifest,
        attestation=attestation,
    )

    snapshot_manifest, snapshot_directory = build_snapshot(
        raw=built_batch.raw,
        manifest=built_batch.manifest,
        decision=outcome.decision,
        output_root=output / "client01" / "snapshots",
        lineage_store=LineageStore(output / "lineage"),
        preprocessing_config=dict(config["preprocessing"]),
        source_dataset=str(config["experiment"]["dataset"]),
        source_dataset_version="fixture-phase1",
        code_version=__version__,
    )

    summary = {
        "schema_version": "1.0",
        "experiment_id": experiment_id,
        "created_at": utc_now(),
        "trust_level": "software-development",
        "attestation_id": attestation.result_id,
        "batch_id": built_batch.manifest.core.batch_id,
        "batch_chain_hash": built_batch.manifest.chain_hash,
        "admission_status": outcome.decision.status,
        "decision_id": outcome.decision.decision_id,
        "receipt_id": outcome.receipt.core.receipt_id,
        "snapshot_id": snapshot_manifest.snapshot_id,
        "snapshot_dataset_digest": snapshot_manifest.dataset_digest,
        "feature_count": len(snapshot_manifest.feature_names),
        "window_count": sum(snapshot_manifest.split_counts.values()),
        "paths": {
            "attestation": str(attestation_path.relative_to(output)),
            "batch_directory": str(built_batch.queue_directory.relative_to(output)),
            "snapshot_directory": str(snapshot_directory.relative_to(output)),
            "identity_registry": "registry/identity_registry.json",
            "vault": "vault",
        },
    }
    write_json_once(output / "summary.json", summary)
    return summary

