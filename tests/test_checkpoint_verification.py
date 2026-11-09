"""Witness-aware checkpoint dispatch retains the full authenticated phase gate."""

import pytest
from cryptography.hazmat.primitives import serialization
from test_witness_phase import _admit
from test_witness_phase import integrated as _integrated

from fl_forensics.checkpoint_verification import verify_witness_checkpoint
from fl_forensics.storage import write_json_once, write_once

integrated = _integrated


@pytest.mark.parametrize("explicit_profile", [True, False])
def test_standard_campaign_cannot_silently_ignore_witness_profile(
    tmp_path, monkeypatch, explicit_profile
):
    from test_secure_campaign import SecureCampaignTests

    from fl_forensics import secure_campaign as campaigns
    from fl_forensics.secure_round import SecureRoundError

    fixture = SecureCampaignTests()
    campaign, partition, evaluation = fixture._workspace(tmp_path)
    monkeypatch.setattr(campaigns, "EXPECTED_CLIENTS", ["client01", "client02"])
    monkeypatch.setattr(campaigns, "dependencies", lambda: ())
    profile = {"profile": "closed-witness-live-round-v1"} if explicit_profile else None
    if not explicit_profile:
        (campaign / "rounds/round-001/witness-round").mkdir()
    with pytest.raises(SecureRoundError, match="requires an in-round"):
        campaigns.finalize_secure_campaign(
            workspace=campaign,
            trust_workspace=tmp_path / "trust",
            partition_manifest_path=partition,
            server_evaluation_path=evaluation,
            expected_rounds=2,
            verification_profile=profile,
            profile_root=tmp_path,
        )


def retain_profile(d, proof, root):
    root.mkdir(parents=True, exist_ok=True)
    write_json_once(root / "snapshot.json", proof["snapshot"].model_dump(mode="json"))
    write_once(root / "witness.pem", d.witness_store.signer.public_pem())
    write_once(root / "coordinator.pem", d.fixture.coordinator.public_pem())
    write_once(root / "trust.pem", proof["trust_store"])
    locations = {}
    for name, key in proof["client_public_keys"].items():
        filename = name + ".pem"
        write_once(
            root / filename,
            key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
        )
        locations[name] = filename
    write_json_once(root / "keys.json", locations)
    acks = []
    for i, ack in enumerate(proof["retained_acknowledgements"]):
        name = f"ack-{i}.json"
        write_json_once(root / name, ack.model_dump(mode="json"))
        acks.append(name)
    return {
        "profile": "closed-witness-live-round-v1",
        "rounds": {
            "1": {
                "snapshot": "snapshot.json",
                "expected_policy_digest": proof["expected_policy_digest"],
                "expected_closure_digest": proof["expected_closure_digest"],
                "witness_public_key": "witness.pem",
                "coordinator_public_key": "coordinator.pem",
                "client_keys": "keys.json",
                "tsa_trust_store": "trust.pem",
                "acknowledgements": acks,
            }
        },
    }


def checkpoint_options(d, profile, root):
    options = d._options()
    options.pop("submissions_root")
    return dict(options, verification_profile=profile, profile_root=root)


def test_real_round_dispatch_reconstructs_witness_phase(integrated, tmp_path):
    d = integrated
    proof = d.close_witness()
    assert _admit(d, proof)["status"] == "verified_witness_round"
    root = tmp_path / "profile"
    profile = retain_profile(d, proof, root)
    result = verify_witness_checkpoint(**checkpoint_options(d, profile, root))
    assert result["status"] == "verified" and result["deadline_verified"]
    assert result["phase_order_verified"] and result["coefficients_verified"]
    assert result["witness_verification"]["registration_set_verified"]
    assert not result["delivery_verified"]


@pytest.mark.parametrize(
    "change", ["policy", "head", "receipt", "snapshot", "no-profile", "uncovered-round"]
)
def test_dispatch_cannot_downgrade_or_substitute_witness_evidence(integrated, tmp_path, change):
    d = integrated
    proof = d.close_witness()
    assert _admit(d, proof)["status"] == "verified_witness_round"
    root = tmp_path / "profile"
    profile = retain_profile(d, proof, root)
    if change in {"policy", "head"}:
        field = "expected_policy_digest" if change == "policy" else "expected_closure_digest"
        profile["rounds"]["1"][field] = "0" * 64
    elif change == "receipt":
        d._remove(d.workspace / "witness-round/receipt.json")
    elif change == "snapshot":
        d._remove(root / "snapshot.json")
    elif change == "no-profile":
        profile = None
    elif change == "uncovered-round":
        profile["rounds"] = {"2": profile["rounds"]["1"]}
    try:
        report = verify_witness_checkpoint(**checkpoint_options(d, profile, root))
    except (ValueError, OSError):
        return
    assert report["status"] == "failed"
    assert report["witness_verification"]["status"] == "invalid"


def test_m7_dispatch_requires_external_profile_and_never_calls_legacy(tmp_path, monkeypatch):
    from fl_forensics import prediction_bundle as m7

    round_root = tmp_path / "round"
    validation = tmp_path / "partition/server/splits/validation.json"
    write_json_once(validation, {"rows": {}})
    from fl_forensics.canonical import sha256_file

    write_json_once(
        round_root / "checkpoint/manifest.json",
        {"artifact_type": "in_round_secure_global_checkpoint"},
    )
    write_json_once(
        round_root / "public/partition-manifest.json",
        {
            "server_evaluation_splits": {
                "validation": {
                    "path": "server/splits/validation.json",
                    "sha256": sha256_file(validation),
                }
            }
        },
    )
    (round_root / "witness-round").mkdir()
    monkeypatch.setattr(m7, "_verify_partition_snapshot_files", lambda **kw: None)

    def legacy(**kw):
        raise AssertionError("witnessed checkpoint reached legacy fallback")

    monkeypatch.setattr(m7, "verify_in_round_secure_round", legacy)
    with pytest.raises(ValueError, match="explicit trusted"):
        m7._verify_round_checkpoint(
            round_workspace=round_root,
            trust_workspace=tmp_path / "trust",
            partition_workspace=tmp_path / "partition",
        )
