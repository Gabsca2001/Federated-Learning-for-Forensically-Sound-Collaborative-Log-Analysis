"""Creation and verification helpers for signed Attestation Results.

This phase models the Verifier output artifact. It does not yet implement a
TPM2 Quote, PCR replay, or IMA appraisal; those enter through the same model in
M4 and must set the corresponding `trust_level`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ec

from .canonical import digest_object
from .crypto import DigestSigner, public_key_id, verify_digest_signature
from .models import AttestationResult, AttestationResultCore, SignatureBlock
from .trust_models import AttestationResultCoreV2, AttestationResultV2


def create_attestation_result(
    core: AttestationResultCore,
    signer: DigestSigner,
    *,
    trust_level: str = "software-development",
) -> AttestationResult:
    core_digest = digest_object(core.model_dump(mode="json"))
    return AttestationResult(
        result_id=f"attestation-{core_digest[:24]}",
        core=core,
        core_digest=core_digest,
        signature=SignatureBlock(
            key_id=signer.key_id,
            value_b64=signer.sign_digest(core_digest),
            trust_level=trust_level,
        ),
    )


def create_attestation_result_v2(
    core: AttestationResultCoreV2,
    signer: DigestSigner,
    *,
    trust_level: str,
) -> AttestationResultV2:
    """Create the M4 result without changing preserved M1 schema-v1 objects."""

    core_digest = digest_object(core.model_dump(mode="json"))
    return AttestationResultV2(
        result_id=f"attestation-{core_digest[:24]}",
        core=core,
        core_digest=core_digest,
        signature=SignatureBlock(
            key_id=signer.key_id,
            value_b64=signer.sign_digest(core_digest),
            trust_level=trust_level,
        ),
    )


def create_development_attestation(
    *,
    node_id: str,
    client_id: str,
    signer: DigestSigner,
    quote_digest: str,
    measurement_log_digest: str,
    nonce: str,
    lifetime_seconds: int = 900,
) -> AttestationResult:
    now = datetime.now(UTC)
    core = AttestationResultCore(
        node_id=node_id,
        client_id=client_id,
        status="passed",
        nonce=nonce,
        pcr_selection=[0, 2, 4, 7, 10],
        quote_digest=quote_digest,
        measurement_log_digest=measurement_log_digest,
        policy_id="development-attestation",
        policy_version="1.0.0",
        baseline_id="development-baseline",
        baseline_version="1.0.0",
        evaluated_at=now.isoformat().replace("+00:00", "Z"),
        expires_at=(now + timedelta(seconds=lifetime_seconds))
        .isoformat()
        .replace("+00:00", "Z"),
        reasons=["phase-1 development artifact; no TPM2 Quote appraisal performed"],
    )
    return create_attestation_result(core, signer, trust_level="software-development")


def verify_attestation_signature(
    result: AttestationResult | AttestationResultV2,
    verifier_public_key: ec.EllipticCurvePublicKey,
) -> bool:
    core_digest = digest_object(result.core.model_dump(mode="json"))
    return (
        core_digest == result.core_digest
        and result.signature.key_id == public_key_id(verifier_public_key)
        and verify_digest_signature(
            verifier_public_key, result.core_digest, result.signature.value_b64
        )
    )
