"""Read-only verification of a phase-1 demo workspace."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .attestation import verify_attestation_signature
from .canonical import batch_chain_hash, digest_object, sha256_bytes
from .crypto import load_public_key, public_key_id, verify_digest_signature
from .models import AttestationResult, BatchManifest, IdentityRecord, SignedReceipt, SnapshotManifest
from .storage import load_json
from .vault import EvidenceVault


def verify_workspace(workspace: Path) -> dict[str, Any]:
    errors: list[str] = []
    summary = load_json(workspace / "summary.json")
    registry = load_json(workspace / summary["paths"]["identity_registry"])
    identities = {
        item["client_id"]: IdentityRecord.model_validate(item)
        for item in registry["identities"]
    }
    verifier_key = load_public_key(registry["verifier_public_key_pem"].encode("utf-8"))
    repository_key = load_public_key(registry["repository_public_key_pem"].encode("utf-8"))

    attestation = AttestationResult.model_validate(
        load_json(workspace / summary["paths"]["attestation"])
    )
    if not verify_attestation_signature(attestation, verifier_key):
        errors.append("attestation signature or core digest is invalid")

    batch_directory = workspace / summary["paths"]["batch_directory"]
    manifest = BatchManifest.model_validate(load_json(batch_directory / "manifest.json"))
    raw_path = batch_directory / manifest.core.content_filename
    raw = raw_path.read_bytes()
    if sha256_bytes(raw) != manifest.core.content_sha256:
        errors.append("queued raw batch digest does not match manifest")
    core_dict = manifest.core.model_dump(mode="json")
    if digest_object(core_dict) != manifest.canonical_core_sha256:
        errors.append("batch canonical core digest is invalid")
    if (
        batch_chain_hash(
            manifest.core.previous_chain_hash,
            manifest.core.content_sha256,
            core_dict,
        )
        != manifest.chain_hash
    ):
        errors.append("batch chain commitment is invalid")
    identity = identities.get(manifest.core.client_id)
    if identity is None:
        errors.append("batch client identity is missing")
    else:
        evidence_key = load_public_key(identity.evidence_public_key_pem.encode("utf-8"))
        if (
            public_key_id(evidence_key) != manifest.signature.key_id
            or not verify_digest_signature(
                evidence_key, manifest.chain_hash, manifest.signature.value_b64
            )
        ):
            errors.append("batch evidence signature is invalid")

    vault = EvidenceVault(workspace / summary["paths"]["vault"])
    errors.extend(vault.verify_integrity())
    state = load_json(vault.state_path)
    position_key = vault.position_key(
        manifest.core.client_id,
        manifest.core.acquisition_session_id,
        manifest.core.sequence_number,
    )
    position = state["positions"].get(position_key)
    if not position or not position.get("receipt_path"):
        errors.append("repository receipt is missing from the operational index")
    else:
        receipt = SignedReceipt.model_validate(
            load_json(vault.root / position["receipt_path"])
        )
        if (
            receipt.signature.key_id != public_key_id(repository_key)
            or digest_object(receipt.core.model_dump(mode="json")) != receipt.core_digest
            or not verify_digest_signature(
                repository_key, receipt.core_digest, receipt.signature.value_b64
            )
        ):
            errors.append("repository receipt signature is invalid")

    snapshot_directory = workspace / summary["paths"]["snapshot_directory"]
    snapshot = SnapshotManifest.model_validate(load_json(snapshot_directory / "manifest.json"))
    if sha256_bytes((snapshot_directory / "dataset.json").read_bytes()) != snapshot.dataset_digest:
        errors.append("snapshot dataset digest is invalid")
    if (
        sha256_bytes((snapshot_directory / "window_lineage.json").read_bytes())
        != snapshot.lineage_digest
    ):
        errors.append("snapshot window-lineage digest is invalid")

    return {
        "workspace": str(workspace),
        "status": "verified" if not errors else "failed",
        "error_count": len(errors),
        "errors": errors,
        "batch_id": manifest.core.batch_id,
        "snapshot_id": snapshot.snapshot_id,
    }

