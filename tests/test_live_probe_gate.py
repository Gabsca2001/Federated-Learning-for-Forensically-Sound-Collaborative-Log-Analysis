import json
from types import SimpleNamespace as NS

import pytest
import yaml

import fl_forensics.live_probe_gate as lp
from fl_forensics.canonical import sha256_file
from fl_forensics.composite_admission_models import AdmissionPolicyDecision
from fl_forensics.probe_gate import client_scores, drift_score
from fl_forensics.round_derivation import _graph

K = [(12, 12.0), (17, 12.0)]


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def table(values):
    return [[k[0], k[1], v] for k, v in zip(K, values, strict=True)]


@pytest.fixture
def ws(tmp_path, monkeypatch):
    workspace = tmp_path / "round-002"
    public = workspace / "public"
    base = {"name": "base", "class_names": ["attack", "benign"], "probe": [0.0, 0.0]}
    put(public / "base-model.json", base)
    policy = {
        "profile": lp.PROFILE, "values": [3.0, 6.0, 12.0],
        "client": {"floor": 0.1, "multiplier": 2.0, "scales": table([0.5, 0.1])},
        "global": {"floor": 0.1, "multiplier": 1.5, "scales": table([0.4, 0.1]),
                   "initial_model_sha256": "0" * 64, "initial_shortcuts": table([0.0, 0.0])},
    }
    put(public / lp.POLICY_FILE, policy)
    cfg = {"runtime_admission": {"probe_policy": {"profile": lp.PROFILE, "mode": "enforce",
                                                  "policy_sha256": sha256_file(public / lp.POLICY_FILE)}}}
    (public / "in-round-admission.yaml").write_text(yaml.safe_dump(cfg))
    # Model exports carry their probe shortcuts directly; torch evaluation is out of scope here.
    monkeypatch.setattr(lp, "_probe_context", lambda rows, base: lambda export: dict(zip(K, export["probe"], strict=True)))
    records, state = [], {}
    shortcut = {f"h{i}": [0.1, 0.0] for i in range(6)}
    shortcut["x"] = [0.1, 0.3]  # stable feature 17 moved 3x its clean scale -> flagged
    shortcut["n"] = [0.9, 0.0]  # noisy feature 12 moved 1.6x its clean scale -> accepted
    for c, v in shortcut.items():
        sub = tmp_path / "sub" / c
        put(sub / "update.json", {"probe": v})
        records.append({"client_id": c, "bundle": NS(), "bundle_sha256": c.ljust(64, "0")[:64].replace("h", "a").replace("x", "b").replace("n", "c"), "submission": sub})
        ok = AdmissionPolicyDecision(policy="tpm_only", status="accepted", contributes=True, score=0.0, reasons=["ok"])
        state[c] = {"primary": ok, "policies": [ok]}
    return NS(workspace=workspace, public=public, base=base, records=records, state=state)


def run(ws, create):
    return lp.apply_client_probe(workspace=ws.workspace, records=ws.records, base=ws.base,
                                 validation_rows=[], statistical_state=ws.state, create=create)


def test_scores_are_per_key_normalised():
    per = {f"h{i}": {K[0]: 0.1, K[1]: 0.0} for i in range(6)} | {"x": {K[0]: 0.1, K[1]: 0.3}}
    s = client_scores(per, {K[0]: 0.5, K[1]: 0.1})
    assert s["x"][1] == [17, 12.0] and s["x"][0] == pytest.approx(3.0)
    assert drift_score({K[0]: 0.3, K[1]: 0.2}, {K[0]: 0.0, K[1]: 0.0}, {K[0]: 0.4, K[1]: 0.1})[1] == [17, 12.0]


def test_flagged_client_gets_signed_zero_mass_primary_and_replays(ws):
    state = run(ws, True)
    assert state["x"]["primary"].policy == "probe_keynorm" and not state["x"]["primary"].contributes
    assert state["x"]["primary"].status == "statistically_quarantined"
    assert state["n"]["primary"].contributes and all(state[f"h{i}"]["primary"].contributes for i in range(6))
    run(ws, False)  # verifier recomputes identical bytes


def test_tampered_client_result_is_rejected(ws):
    run(ws, True)
    path = ws.workspace / lp.CLIENT_RESULT
    value = json.loads(path.read_text()); value["scores"]["x"]["flagged"] = False
    path.chmod(0o644); path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="replay mismatch"):
        run(ws, False)


def test_changed_policy_file_is_rejected(ws):
    path = ws.public / lp.POLICY_FILE
    value = json.loads(path.read_text()); value["client"]["multiplier"] = 100.0
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="policy changed"):
        run(ws, True)


def test_audit_only_records_but_does_not_exclude(ws):
    p = ws.public / "in-round-admission.yaml"; cfg = yaml.safe_load(p.read_text())
    cfg["runtime_admission"]["probe_policy"]["mode"] = "audit_only"; p.write_text(yaml.safe_dump(cfg))
    state = run(ws, True)
    assert state["x"]["primary"].contributes
    assert json.loads((ws.workspace / lp.CLIENT_RESULT).read_text())["scores"]["x"]["flagged"]


def test_rollback_keeps_previous_model_and_commits_candidate(ws):
    candidate = {"name": "candidate", "probe": [0.0, 0.2]}  # drift 2.0 > 1.5 on feature 17
    model = lp.apply_rollback(workspace=ws.workspace, base=ws.base, candidate=candidate, validation_rows=[], create=True)
    assert model == ws.base and lp.rolled_back(ws.workspace)
    assert json.loads((ws.workspace / lp.REJECTED).read_text()) == candidate
    assert lp.apply_rollback(workspace=ws.workspace, base=ws.base, candidate=candidate, validation_rows=[], create=False) == ws.base
    with pytest.raises(ValueError, match="replay mismatch"):
        lp.apply_rollback(workspace=ws.workspace, base=ws.base, candidate={"name": "other", "probe": [0.0, 0.2]}, validation_rows=[], create=False)


def test_small_drift_keeps_candidate(ws):
    candidate = {"name": "candidate", "probe": [0.5, 0.1]}  # 1.25 and 1.0, below 1.5
    assert lp.apply_rollback(workspace=ws.workspace, base=ws.base, candidate=candidate, validation_rows=[], create=True) == candidate
    assert not (ws.workspace / lp.REJECTED).exists() and not lp.rolled_back(ws.workspace)


def test_first_round_requires_declared_initial_model(ws, tmp_path):
    first = tmp_path / "round-001"; ws.workspace.rename(first)
    with pytest.raises(ValueError, match="initial model"):
        lp.apply_rollback(workspace=first, base=ws.base, candidate=ws.base, validation_rows=[], create=True)


def _graph_for(ws, rollback):
    for relative in ("derivation/input-inventory.json", "derivation/binding.json", "derivation/scoring-state.json"):
        put(ws.workspace / relative, {"test": True})
    run(ws, True)
    candidate = {"name": "candidate", "probe": [0.0, 0.2 if rollback else 0.0]}
    lp.apply_rollback(workspace=ws.workspace, base=ws.base, candidate=candidate, validation_rows=[], create=True)
    ctx = NS(core_digest="a" * 64, core=NS(base_model_sha256="d" * 64))
    rec = ws.records[-2]  # client "x"
    entry = NS(submission_id="submission-x", outcome="ready_for_admission", receipt_core_digests=[])
    disposition = NS(submission_id="submission-x", client_id="x", bundle_sha256=rec["bundle_sha256"],
                     trust_decision_sha256="8" * 64, decision_sha256="b" * 64, participated_in_scoring=True,
                     effective_weight_decimal="0", model_dump=lambda **kw: {"test": 1})
    scoring = NS(core=NS(admission_contract_sha256="c" * 64, validation_split_sha256="f" * 64, scored_client_ids=["x"]))
    nodes, edges = _graph(workspace=ws.workspace, context=ctx, inventory=NS(core=NS(entries=[entry])),
                          dispositions=[disposition], scoring=scoring, checkpoint_hash="9" * 64, status="aggregated")
    kinds = {n.kind: n.node_id for n in nodes}
    return kinds, {(e.source, e.target, e.kind) for e in edges}


def test_graph_links_probe_to_decision_and_rollback_to_checkpoint(ws):
    kinds, links = _graph_for(ws, rollback=True)
    probe, decision, check = kinds["probe_gate_derivation"], kinds["admission_decision"], kinds["checkpoint"]
    assert (kinds["update_bundle"], probe, "num") in links and (probe, decision, "dec") in links
    assert (kinds["global_probe_decision"], check, "dec") in links
    assert (kinds["rejected_candidate"], kinds["global_probe_decision"], "num") in links
    assert (kinds["base_model"], check, "num") in links


def test_graph_without_rollback_has_no_rejected_candidate(ws):
    kinds, _ = _graph_for(ws, rollback=False)
    assert "global_probe_decision" in kinds and "rejected_candidate" not in kinds
