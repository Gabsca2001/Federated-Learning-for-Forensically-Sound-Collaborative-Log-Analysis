"""Admission Controller for phase-1 batch bundles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric import ec

from .attestation import verify_attestation_signature
from .canonical import batch_chain_hash, digest_object, sha256_bytes
from .crypto import DigestSigner, load_public_key, public_key_id, verify_digest_signature
from .models import (
    AdmissionDecision,
    AttestationResult,
    BatchManifest,
    CheckResult,
    IdentityRecord,
    ReceiptCore,
    SignatureBlock,
    SignedReceipt,
)
from .storage import utc_now
from .trust_models import AttestationResultV2
from .vault import EvidenceVault


@dataclass(frozen=True)
class AdmissionOutcome:
    decision: AdmissionDecision
    receipt: SignedReceipt
    idempotent_replay: bool = False


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


class AdmissionController:
    def __init__(
        self,
        *,
        identities: dict[str, IdentityRecord],
        verifier_public_key: ec.EllipticCurvePublicKey,
        repository_signer: DigestSigner,
        vault: EvidenceVault,
        repository_id: str = "evidence-vault-01",
        policy_id: str = "batch-admission",
        policy_version: str = "1.0.0",
        required_attestation_trust_levels: set[str] | None = None,
    ) -> None:
        self.identities = identities
        self.verifier_public_key = verifier_public_key
        self.repository_signer = repository_signer
        self.vault = vault
        self.repository_id = repository_id
        self.policy_id = policy_id
        self.policy_version = policy_version
        self.required_attestation_trust_levels = required_attestation_trust_levels

    def process(
        self,
        *,
        raw: bytes,
        manifest: BatchManifest,
        attestation: AttestationResult | AttestationResultV2,
        now: datetime | None = None,
    ) -> AdmissionOutcome:
        existing = self.vault.existing_submission(manifest)
        if (
            existing is not None
            and existing.chain_hash == manifest.chain_hash
            and sha256_bytes(raw) == manifest.core.content_sha256
        ):
            if existing.receipt is None:
                raise RuntimeError("submission was persisted without a receipt")
            return AdmissionOutcome(existing.decision, existing.receipt, True)

        now = now or datetime.now(UTC)
        checks: list[CheckResult] = []

        def check(name: str, passed: bool, detail: str) -> None:
            checks.append(CheckResult(name=name, passed=passed, detail=detail))

        identity = self.identities.get(manifest.core.client_id)
        check("registered_identity", identity is not None, "identity record found" if identity else "unknown client")

        identity_binding = bool(
            identity
            and identity.status == "active"
            and identity.client_id == manifest.core.client_id
            and identity.node_id == manifest.core.node_id
            and _parse_utc(identity.valid_from) <= now <= _parse_utc(identity.valid_until)
        )
        check("client_node_binding", identity_binding, "active client/node/key validity binding")

        actual_content_digest = sha256_bytes(raw)
        check(
            "content_digest",
            actual_content_digest == manifest.core.content_sha256,
            f"observed={actual_content_digest}",
        )
        check(
            "content_size",
            len(raw) == manifest.core.content_size_bytes,
            f"observed={len(raw)}",
        )

        core_dict = manifest.core.model_dump(mode="json")
        actual_core_digest = digest_object(core_dict)
        actual_chain_hash = batch_chain_hash(
            manifest.core.previous_chain_hash,
            manifest.core.content_sha256,
            core_dict,
        )
        check(
            "canonical_chain_commitment",
            actual_core_digest == manifest.canonical_core_sha256
            and actual_chain_hash == manifest.chain_hash,
            f"core={actual_core_digest};chain={actual_chain_hash}",
        )

        signature_valid = False
        if identity:
            try:
                evidence_key = load_public_key(identity.evidence_public_key_pem.encode("utf-8"))
                signature_valid = (
                    identity.evidence_key_id == manifest.signature.key_id
                    and public_key_id(evidence_key) == identity.evidence_key_id
                    and verify_digest_signature(
                        evidence_key, manifest.chain_hash, manifest.signature.value_b64
                    )
                )
            except ValueError:
                signature_valid = False
        check("evidence_signature", signature_valid, "ESK signature and registered key binding")

        attestation_object_digest = digest_object(attestation.model_dump(mode="json"))
        attestation_reference_valid = (
            manifest.core.attestation_id == attestation.result_id
            and manifest.core.attestation_digest == attestation_object_digest
        )
        check("attestation_reference", attestation_reference_valid, "manifest references exact result")

        attestation_signature_valid = verify_attestation_signature(
            attestation, self.verifier_public_key
        )
        check(
            "attestation_signature",
            attestation_signature_valid,
            "Verifier signature and core digest",
        )
        attestation_identity = (
            attestation.core.client_id == manifest.core.client_id
            and attestation.core.node_id == manifest.core.node_id
        )
        check("attestation_identity_binding", attestation_identity, "result belongs to client/node")
        status_valid = attestation.core.status in {"passed", "passed_with_warning"}
        check("attestation_status", status_valid, f"status={attestation.core.status}")
        freshness_valid = _parse_utc(attestation.core.expires_at) >= now
        check("attestation_freshness", freshness_valid, f"expires={attestation.core.expires_at}")
        if self.required_attestation_trust_levels is not None:
            trust_valid = attestation.signature.trust_level in self.required_attestation_trust_levels
            check(
                "attestation_trust_level",
                trust_valid,
                f"trust_level={attestation.signature.trust_level}",
            )

        continuity_valid, continuity_detail = self.vault.expected_continuity(manifest)
        if existing is not None and existing.chain_hash != manifest.chain_hash:
            continuity_valid = False
            continuity_detail = "same client/session/sequence already has a different commitment"
        check("session_sequence_continuity", continuity_valid, continuity_detail)

        accepted = all(item.passed for item in checks)
        status = "accepted" if accepted else "quarantined"
        decision_basis = {
            "batch_id": manifest.core.batch_id,
            "status": status,
            "manifest_digest": digest_object(manifest.model_dump(mode="json")),
            "content_digest": actual_content_digest,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "decided_at": utc_now(),
            "checks": [item.model_dump(mode="json") for item in checks],
        }
        decision_id = f"decision-{digest_object(decision_basis)[:24]}"
        decision = AdmissionDecision(decision_id=decision_id, **decision_basis)
        self.vault.persist_submission(
            raw=raw,
            manifest=manifest,
            attestation=attestation,
            decision=decision,
        )

        receipt_core = ReceiptCore(
            receipt_id=f"receipt-{decision_id.removeprefix('decision-')}",
            batch_id=manifest.core.batch_id,
            chain_hash=manifest.chain_hash,
            decision_id=decision_id,
            admission_status=status,
            repository_id=self.repository_id,
            received_at=utc_now(),
            policy_id=self.policy_id,
            policy_version=self.policy_version,
        )
        receipt_digest = digest_object(receipt_core.model_dump(mode="json"))
        receipt = SignedReceipt(
            core=receipt_core,
            core_digest=receipt_digest,
            signature=SignatureBlock(
                key_id=self.repository_signer.key_id,
                value_b64=self.repository_signer.sign_digest(receipt_digest),
                trust_level="software-development",
            ),
        )
        self.vault.persist_receipt(manifest, receipt)
        return AdmissionOutcome(decision, receipt)
