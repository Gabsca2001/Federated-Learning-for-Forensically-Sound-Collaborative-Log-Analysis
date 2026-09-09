from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


SPEC = importlib.util.spec_from_file_location(
    "render_m8_disagreement_preservation_summary",
    Path("scripts/render_m8_disagreement_preservation_summary.py"),
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load the M8 disagreement result renderer")
REPORTING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORTING)


def _policy(
    name: str,
    *,
    accepted: int,
    downweighted: int,
    quarantined: int,
    true_positive: int,
    false_negative: int,
) -> SimpleNamespace:
    return SimpleNamespace(
        policy=name,
        accepted_count=accepted,
        downweighted_count=downweighted,
        quarantined_count=quarantined,
        controlled_true_positive=true_positive,
        controlled_false_positive=0,
        controlled_true_negative=30,
        controlled_false_negative=false_negative,
    )


def test_policy_rows_distinguish_contributors_from_quarantines() -> None:
    report = SimpleNamespace(
        core=SimpleNamespace(
            policy_outcomes=[
                _policy(
                    "tpm_only",
                    accepted=390,
                    downweighted=0,
                    quarantined=60,
                    true_positive=60,
                    false_negative=30,
                ),
                _policy(
                    "statistics_only",
                    accepted=388,
                    downweighted=0,
                    quarantined=62,
                    true_positive=60,
                    false_negative=30,
                ),
                _policy(
                    "sequential",
                    accepted=358,
                    downweighted=0,
                    quarantined=92,
                    true_positive=90,
                    false_negative=0,
                ),
                _policy(
                    "gated_composite",
                    accepted=334,
                    downweighted=24,
                    quarantined=92,
                    true_positive=90,
                    false_negative=0,
                ),
            ]
        )
    )

    rows = REPORTING._policy_rows(report)

    assert [row["policy"] for row in rows] == [
        "tpm_only",
        "statistics_only",
        "sequential",
        "gated_composite",
    ]
    assert rows[0]["controlled_unsafe_recall"] == pytest.approx(2 / 3)
    assert rows[2]["controlled_unsafe_recall"] == 1.0
    assert rows[3]["deployed_for_training"] is True
    assert rows[3]["contributing_count"] == 358
    assert rows[3]["quarantined_count"] == 92


def test_validate_public_sources_rejects_a_different_selected_model() -> None:
    campaign = SimpleNamespace(
        source_campaign_id="campaign-1",
        source_disagreement_experiment_id="experiment-1",
        source_disagreement_contract_id="contract-1",
        source_campaign_manifest_sha256="a" * 64,
        selected_round=11,
        selected_model_sha256="b" * 64,
    )
    receipt = SimpleNamespace(
        core=SimpleNamespace(campaign_accounting=campaign)
    )
    m6 = {
        "artifact_type": "published_m6_live_disagreement_snapshot",
        "campaign_id": "campaign-1",
        "experiment_id": "experiment-1",
        "contract_id": "contract-1",
        "source_campaign_manifest_sha256": "a" * 64,
        "selected_round": 11,
    }
    m7 = {
        "artifact_type": "published_m7_m6_investigation_summary",
        "campaign_id": "campaign-1",
        "round_number": 11,
        "global_model_sha256": "c" * 64,
    }

    with pytest.raises(ValueError, match="M7 summary"):
        REPORTING._validate_public_sources(
            receipt=receipt,
            m6_summary=m6,
            m7_summary=m7,
        )


def test_published_summary_must_match_its_manifest(tmp_path: Path) -> None:
    summary = tmp_path / "summary.json"
    summary.write_text("{}\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        "{\"artifact_type\":\"expected\",\"files\":{\"summary.json\":{"
        "\"sha256\":\""
        + REPORTING._sha256(summary)
        + "\",\"size_bytes\":3}}}\n",
        encoding="utf-8",
    )

    loaded = REPORTING._verify_published_summary(
        manifest_path=manifest,
        summary_path=summary,
        expected_artifact_type="expected",
    )
    assert loaded["artifact_type"] == "expected"

    summary.write_text("{\"changed\":true}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="differs from its manifest"):
        REPORTING._verify_published_summary(
            manifest_path=manifest,
            summary_path=summary,
            expected_artifact_type="expected",
        )
