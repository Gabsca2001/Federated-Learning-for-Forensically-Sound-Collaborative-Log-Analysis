from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location(
    "render_live_contribution_explanations_summary",
    Path("scripts/render_live_contribution_explanations_summary.py"),
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load the live-contribution result renderer")
REPORTING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORTING)


def _item(
    status: str,
    *,
    round_number: int,
    client_id: str,
    score: float,
    risk: float,
    trust_admissible: bool = True,
) -> dict[str, object]:
    downweight = 0.3
    quarantine = 0.6
    return {
        "round_number": round_number,
        "client_id": client_id,
        "final_status": status,
        "composite_score": score,
        "composite_downweight_threshold": downweight,
        "composite_quarantine_threshold": quarantine,
        "signed_headroom_to_full_acceptance": downweight - score,
        "signed_headroom_to_quarantine": quarantine - score,
        "statistical_risk": risk,
        "trust": {"admissible": trust_admissible},
        "policy_explanations": [
            {
                "policy": policy,
                "status": status,
                "contributes": status in {"accepted", "accepted_downweighted"},
                "score": score,
                "hard_trust_veto_applied": not trust_admissible
                and policy != "statistics_only",
            }
            for policy in REPORTING.POLICIES
        ],
        "aggregation_treatment": {
            "retained_weight_fraction": 1.0 if status == "accepted" else 0.0,
            "included_in_checkpoint": status == "accepted",
            "admitted_aggregate_influence_l2": 0.01,
            "full_weight_counterfactual_aggregate_shift_l2": 0.02,
        },
        "counterfactual": {"trust_remediation_required": not trust_admissible},
    }


def test_policy_rows_keep_shadow_and_deployed_outcomes_separate() -> None:
    explanations = [
        _item("accepted", round_number=1, client_id="client01", score=0.1, risk=0.2),
        _item(
            "trust_quarantined",
            round_number=1,
            client_id="client02",
            score=0.5,
            risk=0.0,
            trust_admissible=False,
        ),
    ]
    rows = REPORTING._policy_rows(explanations)
    assert [row["policy"] for row in rows] == list(REPORTING.POLICIES)
    assert rows[0]["hard_trust_veto_count"] == 1
    assert rows[1]["hard_trust_veto_count"] == 0
    assert rows[3]["decision_count"] == 2


def test_case_studies_use_declared_boundary_rules() -> None:
    explanations = [
        _item("accepted", round_number=1, client_id="a", score=0.1, risk=0.2),
        _item("accepted", round_number=2, client_id="b", score=0.29, risk=0.3),
        _item(
            "accepted_downweighted",
            round_number=1,
            client_id="c",
            score=0.31,
            risk=0.4,
        ),
        _item(
            "accepted_downweighted",
            round_number=2,
            client_id="d",
            score=0.55,
            risk=0.5,
        ),
        _item(
            "statistically_quarantined",
            round_number=1,
            client_id="e",
            score=0.61,
            risk=0.8,
        ),
        _item(
            "statistically_quarantined",
            round_number=2,
            client_id="f",
            score=0.9,
            risk=0.9,
        ),
        _item(
            "trust_quarantined",
            round_number=1,
            client_id="g",
            score=0.5,
            risk=0.1,
            trust_admissible=False,
        ),
        _item(
            "trust_quarantined",
            round_number=2,
            client_id="h",
            score=0.8,
            risk=0.6,
            trust_admissible=False,
        ),
    ]
    cases = {
        case_id: item
        for case_id, _rule, item in REPORTING._representative_cases(explanations)
    }
    assert cases["accepted-nearest-quarantine"]["client_id"] == "b"
    assert cases["downweighted-nearest-full-weight"]["client_id"] == "c"
    assert cases["statistical-quarantine-nearest-boundary"]["client_id"] == "e"
    assert cases["trust-statistics-disagreement"]["client_id"] == "g"


def test_replacement_rejects_a_modified_published_file(tmp_path: Path) -> None:
    summary = tmp_path / "summary.json"
    summary.write_text("{}\n", encoding="utf-8")
    manifest = {
        "artifact_type": "published_m6_live_contribution_explanations_manifest",
        "source_explanation_bundle_id": "bundle-1",
        "source_explanation_manifest_sha256": "a" * 64,
        "files": {
            "summary.json": {
                "sha256": REPORTING._sha256(summary),
                "size_bytes": summary.stat().st_size,
            }
        },
    }
    (tmp_path / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    assert REPORTING._authorize_replacement(
        tmp_path,
        enabled=True,
        source_bundle_id="bundle-1",
        source_manifest_sha256="a" * 64,
    )
    summary.write_text('{"changed":true}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="changed after publication"):
        REPORTING._authorize_replacement(
            tmp_path,
            enabled=True,
            source_bundle_id="bundle-1",
            source_manifest_sha256="a" * 64,
        )


def test_public_verification_receipt_is_independent_of_host_path() -> None:
    verification = {
        "status": "verified",
        "error_count": 0,
        "workspace": "/host-specific/root/artifacts/reference-bundle",
    }
    receipt = REPORTING._portable_verification_receipt(
        verification,
        source_workspace=Path("artifacts/reference-bundle"),
    )
    assert receipt == {
        "status": "verified",
        "error_count": 0,
        "source_workspace_name": "reference-bundle",
    }
    assert verification["workspace"].startswith("/host-specific/")


def test_committed_snapshot_matches_its_manifest() -> None:
    root = Path("results/m6-live-contribution-explanations-local-test-v1")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["source_explanation_bundle_id"].startswith(
        "m6-live-contribution-explanations-"
    )
    assert len(manifest["files"]) == 11
    for name, metadata in manifest["files"].items():
        path = root / name
        assert path.stat().st_size == metadata["size_bytes"]
        assert REPORTING._sha256(path) == metadata["sha256"]
