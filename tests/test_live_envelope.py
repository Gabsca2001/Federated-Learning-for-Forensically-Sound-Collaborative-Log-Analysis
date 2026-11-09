import copy
from types import SimpleNamespace as NS

import numpy as np
import pytest
import yaml

from fl_forensics.canonical import sha256_file
from fl_forensics.live_envelope import apply_live_envelope, install_assets
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.state_conditioned_audit import fit_state_reference, save_model
from fl_forensics.storage import load_json


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(derived_json_bytes(value))


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    clients = ["a", "b", "c"]
    source = tmp_path / "policy"
    assets = source / "observable-assets"
    assets.mkdir(parents=True)
    workspace = tmp_path / "rounds/round-001"
    public = workspace / "public"
    public.mkdir(parents=True)
    (public / "federation.yaml").write_text("test: true\n")
    put(public / "training-contract.json", {})
    put(
        public / "partition-manifest.json",
        {"test": True, "partition_config_sha256": sha256_file(public / "federation.yaml")},
    )
    cohort = sha256_file(public / "partition-manifest.json")
    cal = {
        "profile": "sequential-round-decision-v1",
        "cohort_id": cohort,
        "clients": clients,
        "horizon": 15,
        "drift": 0.5,
        "minimum_consecutive": 2,
        "centers": [[0, 0]] * 3,
        "scales": [[1, 1]] * 3,
        "instantaneous_limits": [100, 100],
        "cumulative_limits": [100, 100],
        "review_instantaneous_limits": [1, 1],
        "review_cumulative_limits": [2, 2],
        "state_support_limits": {"conditioned": 1000, "state-disabled": 1000},
    }
    env = {
        "profile": "clean-client-risk-envelope-v1",
        "cohort_id": cohort,
        "clients": clients,
        "tensor_risk_limits": [[2, 2]] * 3,
        "retained_peak_fraction": 0.5,
        "state_support_limits": cal["state_support_limits"],
    }
    put(assets / "calibration.json", cal)
    put(assets / "envelope.json", env)
    for view in ("conditioned", "state-disabled"):
        observations = [
            {
                "clients": clients,
                "sizes": [1],
                "cohort_id": cohort,
                "states": np.array([[n], [n + 0.1]]),
                "updates": np.array([[[0.1], [0.2], [0.3]], [[0.2], [0.1], [0.4]]]),
            }
            for n in (0, 1)
        ]
        save_model(
            assets / f"{view}.npz",
            fit_state_reference(observations, condition_on_state=view == "conditioned"),
        )
    value = {
        "runtime_admission": {
            "observable_policy": {
                "profile": "live-client-envelope-retreat-v1",
                "mode": "enforce",
                "assets": {p.name: sha256_file(p) for p in assets.iterdir()},
            }
        }
    }
    config = source / "policy.yaml"
    config.write_text(yaml.safe_dump(value))
    (public / "in-round-admission.yaml").write_bytes(config.read_bytes())
    install_assets(public, config)
    model = {"parameters": [{"name": "x", "shape": [1], "dtype": "float32", "values": [0.0]}]}
    put(public / "base-model.json", model)
    records = []
    state = {}
    for c in clients:
        submission = workspace / "submissions" / c
        put(submission / "update.json", model)
        records.append(
            {
                "client_id": c,
                "bundle": NS(core=NS(num_examples=1)),
                "checks": [NS(passed=True)],
                "bundle_sha256": c * 64,
                "submission": submission,
            }
        )
        state[c] = {"trust": NS(admissible=True), "policies": []}
    context = NS(core=NS(round_number=1), core_digest="a" * 64)
    contract = NS(core=NS(minimum_contributors=2, policy_config_sha256="b" * 64))
    monkeypatch.setattr(
        "fl_forensics.live_envelope.residual_scores",
        lambda *a: {"risk": np.zeros((1, 3)), "state_support_distance": np.array([0.0])},
    )

    def run(create=True, **kw):
        return apply_live_envelope(
            workspace=workspace,
            trust_workspace=tmp_path / "trust",
            validation_split_path=tmp_path / "validation",
            context=context,
            contract=contract,
            records=records,
            base=model,
            statistical_state=copy.deepcopy(state),
            create=create,
            **kw,
        )

    return NS(
        run=run,
        workspace=workspace,
        public=public,
        assets=assets,
        records=records,
        state=state,
        context=context,
        contract=contract,
    )


def test_replay_binds_result_digest_to_the_primary_action(fixture):
    state = fixture.run()
    replay = fixture.run(False)
    pin = sha256_file(fixture.workspace / "observable-policy-result.json")
    assert all(s["primary"].status == "accepted" for s in state.values())
    assert all(
        f"observable-policy-result-sha256:{pin}" in s["primary"].reasons for s in replay.values()
    )


def test_unsupported_state_blocks_all_positive_live_masses(fixture, monkeypatch):
    monkeypatch.setattr(
        "fl_forensics.live_envelope.residual_scores",
        lambda *a: {"risk": np.zeros((1, 3)), "state_support_distance": np.array([2000.0])},
    )
    state = fixture.run()
    assert all(
        s["primary"].status == "statistically_quarantined" and not s["primary"].contributes
        for s in state.values()
    )
    assert not load_json(fixture.workspace / "observable-policy-result.json")["decision"][
        "supported"
    ]


def test_failed_mandatory_gate_cannot_be_rescued_by_benign_statistics(fixture):
    fixture.records[0]["checks"][0].passed = False
    fixture.state["a"]["trust"].admissible = False
    state = fixture.run()
    assert state["a"]["primary"].status == "trust_quarantined"
    assert all(not s["primary"].contributes for s in state.values())


def test_tampered_result_is_rejected_even_when_aggregate_would_be_unchanged(fixture):
    fixture.run()
    target = fixture.workspace / "observable-policy-result.json"
    target.chmod(0o644)
    result = load_json(target)
    result["decision"]["review_required"] = ["a"]
    put(target, result)
    with pytest.raises(ValueError, match="replay mismatch"):
        fixture.run(False)


def test_changed_calibration_is_rejected(fixture):
    target = fixture.public / "observable-assets/envelope.json"
    target.chmod(0o644)
    value = load_json(target)
    value["tensor_risk_limits"][0] = [10, 10]
    put(target, value)
    with pytest.raises(ValueError, match="asset changed"):
        fixture.run()


def test_wrong_cohort_rejected_before_local_training(fixture):
    put(
        fixture.public / "partition-manifest.json",
        {
            "different": True,
            "partition_config_sha256": sha256_file(fixture.public / "federation.yaml"),
        },
    )
    with pytest.raises(ValueError, match="cohort changed"):
        fixture.run()
