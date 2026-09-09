from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location(
    "render_real_attestation_failure_summary",
    Path("scripts/render_real_attestation_failure_summary.py"),
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load the real-attestation result renderer")
REPORTING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORTING)


def _receipt() -> dict[str, object]:
    return {
        "status": "verified",
        "target_client_id": "client03",
        "post_attestation_result_id": "attestation-post",
        "decision_id": "decision-1",
        "authentic_quote_verified": True,
        "failed_measurement_verified": True,
        "fedavg_exclusion_verified": True,
        "error_count": 0,
        "errors": [],
    }


def test_verifier_receipt_requires_all_three_independent_proofs() -> None:
    REPORTING._validate_verifier_receipt(
        _receipt(),
        client_id="client03",
        result_id="attestation-post",
        decision_id="decision-1",
    )

    changed = _receipt()
    changed["authentic_quote_verified"] = False
    with pytest.raises(ValueError, match="authentic_quote_verified"):
        REPORTING._validate_verifier_receipt(
            changed,
            client_id="client03",
            result_id="attestation-post",
            decision_id="decision-1",
        )


def test_verifier_receipt_is_bound_to_target_artifact_ids() -> None:
    with pytest.raises(ValueError, match="post_attestation_result_id"):
        REPORTING._validate_verifier_receipt(
            _receipt(),
            client_id="client03",
            result_id="different-result",
            decision_id="decision-1",
        )


def test_snapshot_replacement_rejects_a_modified_published_file(
    tmp_path: Path,
) -> None:
    summary = tmp_path / "summary.json"
    summary.write_text("{}\n", encoding="utf-8")
    source_digest = "a" * 64
    manifest = {
        "artifact_type": (
            "published_m4_m6_real_attestation_failure_snapshot_manifest"
        ),
        "source_campaign_manifest_sha256": source_digest,
        "files": {"summary.json": {"sha256": REPORTING._sha256(summary)}},
    }
    (tmp_path / "manifest.json").write_text(
        REPORTING._json_bytes(manifest).decode("utf-8"), encoding="utf-8"
    )

    assert REPORTING._authorize_replacement(
        tmp_path,
        enabled=True,
        source_campaign_manifest_sha256=source_digest,
    )

    summary.write_text('{"changed":true}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="existing snapshot file changed"):
        REPORTING._authorize_replacement(
            tmp_path,
            enabled=True,
            source_campaign_manifest_sha256=source_digest,
        )
