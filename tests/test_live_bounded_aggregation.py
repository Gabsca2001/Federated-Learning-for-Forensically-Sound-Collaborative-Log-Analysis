from types import SimpleNamespace as NS

import numpy as np
import pytest
import test_live_envelope as envelope_fixtures
import yaml
from test_live_envelope import put

from fl_forensics.canonical import sha256_file
from fl_forensics.live_bounded_aggregation import backend, materialize, reference
from fl_forensics.round_derivation import _graph


@pytest.fixture
def bounded(tmp_path, monkeypatch):
    fixture = envelope_fixtures.fixture.__wrapped__(tmp_path, monkeypatch)
    p = fixture.public / "observable-assets/bounds.json"
    put(
        p,
        {
            "profile": "clean-common-tensor-l2-cap-v1",
            "cohort_id": sha256_file(fixture.public / "partition-manifest.json"),
            "sizes": [1],
            "limits": [0.1],
        },
    )
    path = fixture.public / "in-round-admission.yaml"
    config = yaml.safe_load(path.read_text())
    config["runtime_admission"]["observable_policy"]["profile"] = "live-client-envelope-bounded-v1"
    config["runtime_admission"]["observable_policy"]["assets"]["bounds.json"] = sha256_file(p)
    path.write_text(yaml.safe_dump(config))
    return fixture


def test_numeric_backend_uses_clipped_deltas(bounded):
    f = backend(bounded.workspace, lambda xs: None)
    arrays = f([([np.array([2.0])], 1.0), ([np.array([-1.0])], 1.0), ([np.array([1.0])], 1.0)])
    np.testing.assert_allclose(arrays, [[1 / 30]])
    assert "bounds_sha256" in f.forensic_profile


def test_changed_bound_commitment_is_rejected(bounded):
    target = bounded.public / "observable-assets/bounds.json"
    target.chmod(0o644)
    put(target, {"changed": True})
    with pytest.raises(ValueError, match="asset changed"):
        reference(bounded.workspace)


def test_wrong_cohort_bound_is_rejected_even_if_file_hash_updated(bounded):
    p = bounded.public / "observable-assets/bounds.json"
    p.chmod(0o644)
    put(
        p,
        {
            "profile": "clean-common-tensor-l2-cap-v1",
            "cohort_id": "0" * 64,
            "sizes": [1],
            "limits": [0.1],
        },
    )
    path = bounded.public / "in-round-admission.yaml"
    config = yaml.safe_load(path.read_text())
    config["runtime_admission"]["observable_policy"]["assets"]["bounds.json"] = sha256_file(p)
    path.write_text(yaml.safe_dump(config))
    with pytest.raises(ValueError, match="cohort mismatch"):
        reference(bounded.workspace)


def test_bounded_profile_cannot_silently_run_audit_only(bounded):
    p = bounded.public / "in-round-admission.yaml"
    cfg = yaml.safe_load(p.read_text())
    cfg["runtime_admission"]["observable_policy"]["mode"] = "audit_only"
    p.write_text(yaml.safe_dump(cfg))
    with pytest.raises(ValueError, match="enforced"):
        reference(bounded.workspace)


def test_derived_artifact_binds_originals_and_replays(bounded):
    decisions = []
    put(bounded.public / "in-round-admission-contract.json", {"core": {"minimum_contributors": 2}})
    for r in bounded.records:
        r["bundle"].core.update_sha256 = "c" * 64
        decisions.append(
            (
                NS(
                    core=NS(
                        client_id=r["client_id"],
                        effective_weight_decimal="1",
                        num_examples=1,
                        m5_checks=[NS(passed=True)],
                    )
                ),
                None,
            )
        )
    materialize(bounded.workspace, bounded.records, decisions, True)
    materialize(bounded.workspace, bounded.records, decisions, False)
    target = bounded.workspace / "bounded-update-derivation.json"
    target.chmod(0o644)
    from fl_forensics.storage import load_json

    value = load_json(target)
    value["bounded"]["limits"] = [100.0]
    put(target, value)
    with pytest.raises(ValueError, match="replay mismatch"):
        materialize(bounded.workspace, bounded.records, decisions, False)


def test_derivation_graph_has_explicit_transform_and_no_direct_raw_edge(bounded):
    for relative in (
        "derivation/input-inventory.json",
        "derivation/binding.json",
        "derivation/scoring-state.json",
        "bounded-update-derivation.json",
    ):
        put(bounded.workspace / relative, {"test": True})
    ctx = NS(core_digest="a" * 64, core=NS(base_model_sha256="d" * 64))
    entry = NS(submission_id="submission-1", outcome="ready_for_admission", receipt_core_digests=[])
    disposition = NS(
        submission_id="submission-1",
        bundle_sha256="e" * 64,
        trust_decision_sha256="8" * 64,
        decision_sha256="b" * 64,
        participated_in_scoring=False,
        effective_weight_decimal="1",
        model_dump=lambda **kw: {"test": 1},
    )
    scoring = NS(
        core=NS(
            admission_contract_sha256="c" * 64,
            validation_split_sha256="f" * 64,
            scored_client_ids=[],
        )
    )
    nodes, edges = _graph(
        workspace=bounded.workspace,
        context=ctx,
        inventory=NS(core=NS(entries=[entry])),
        dispositions=[disposition],
        scoring=scoring,
        checkpoint_hash="9" * 64,
        status="aggregated",
    )
    transform = next(n.node_id for n in nodes if n.kind == "bounded_update_derivation")
    bundle = next(n.node_id for n in nodes if n.kind == "update_bundle")
    checkpoint = next(n.node_id for n in nodes if n.kind == "checkpoint")
    links = {(e.source, e.target, e.kind) for e in edges}
    assert (bundle, transform, "num") in links and (transform, checkpoint, "num") in links
    assert (bundle, checkpoint, "num") not in links


@pytest.mark.parametrize("seed", [0, 1, 3, 7, 8])
def test_more_than_ten_inputs_share_report_and_runtime_order(bounded, seed):
    from fl_forensics.bounded_aggregation import aggregate_bounded

    rng = np.random.default_rng(seed)
    values = [np.array([v]) for v in rng.normal(size=15)]
    entries = [([a], float(i + 1)) for i, a in enumerate(values)]
    actual = backend(bounded.workspace, None)(entries)
    names = [f"client{i:02d}" for i in range(15)]
    expected, _ = aggregate_bounded(
        [[0.0]],
        {c: [a] for c, a in zip(names, values, strict=True)},
        masses={c: i + 1 for i, c in enumerate(names)},
        mandatory_gates=dict.fromkeys(names, True),
        limits=[0.1],
        reference_digest="a" * 64,
        minimum_contributors=1,
    )
    assert all(np.array_equal(a, b) for a, b in zip(actual, expected, strict=True))
