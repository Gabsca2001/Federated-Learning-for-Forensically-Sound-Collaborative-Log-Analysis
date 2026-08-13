"""Export the authoritative Pydantic models as JSON Schema documents."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fl_forensics.models import (
    AdmissionDecision,
    AttestationResult,
    BatchManifest,
    CustodyEvent,
    IdentityRecord,
    SignedReceipt,
    SnapshotManifest,
)
from fl_forensics.trust_models import (
    AttestationChallenge,
    AttestationResultV2,
    EnrollmentRecord,
    EnrollmentRequest,
    MeasurementLog,
    QuoteEvidence,
    RevocationRecord,
)


MODELS = {
    "admission-decision.schema.json": AdmissionDecision,
    "attestation-result.schema.json": AttestationResult,
    "attestation-result-v2.schema.json": AttestationResultV2,
    "batch-manifest.schema.json": BatchManifest,
    "custody-event.schema.json": CustodyEvent,
    "identity-record.schema.json": IdentityRecord,
    "enrollment-record.schema.json": EnrollmentRecord,
    "enrollment-request.schema.json": EnrollmentRequest,
    "attestation-challenge.schema.json": AttestationChallenge,
    "measurement-log.schema.json": MeasurementLog,
    "quote-evidence.schema.json": QuoteEvidence,
    "revocation-record.schema.json": RevocationRecord,
    "repository-receipt.schema.json": SignedReceipt,
    "snapshot-manifest.schema.json": SnapshotManifest,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("configs/schemas"))
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=True)
    for name, model in MODELS.items():
        content = json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        (arguments.output / name).write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
