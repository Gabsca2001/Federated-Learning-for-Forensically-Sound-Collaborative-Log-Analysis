"""Live behavioural probe gate and global rollback over authenticated original bundles.

Opt-in: active only when `runtime_admission.probe_policy` is declared in the bound
in-round-admission.yaml. The policy file (scales, multipliers, campaign initial-model
shortcuts) is frozen before the campaign and pinned by SHA-256 in that configuration, which the
admission contract already pins.

Two coordinator derivations, both recomputed bit-for-bit by the verifier:
* `probe-gate-result.json`: per-key client scores on the original signed updates and the
  resulting decisions. In enforce mode a flagged client receives a `probe_keynorm` primary
  decision with status `statistically_quarantined` (zero mass), so exclusion goes through the
  ordinary signed admission decision and non-compensation rule.
* `probe-rollback-result.json`: global drift of the candidate aggregate. When it exceeds the
  multiplier, the round checkpoint is the previous global model and the rejected candidate is
  kept as `rejected-candidate.json`, committed by digest in the derivation graph.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import numpy as np

from .canonical import sha256_bytes, sha256_file
from .composite_admission_models import AdmissionPolicyDecision
from .config import load_yaml
from .preprocessing import derived_json_bytes
from .probe_gate import client_scores, drift_score, probe_inputs, scale_table, shortcuts
from .storage import load_json, write_once

PROFILE = "live-probe-keynorm-global-rollback-v1"
POLICY_FILE = "probe-policy.json"
CLIENT_RESULT = "probe-gate-result.json"
ROLLBACK_RESULT = "probe-rollback-result.json"
REJECTED = "rejected-candidate.json"


def settings(workspace: Path) -> dict[str, Any] | None:
    path = Path(workspace) / "public/in-round-admission.yaml"
    if not path.exists():
        return None
    value = load_yaml(path)[0].get("runtime_admission", {}).get("probe_policy")
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"profile", "mode", "policy_sha256"}
        or value["profile"] != PROFILE
        or value["mode"] not in ("enforce", "audit_only", "rollback_only")
        or not isinstance(value["policy_sha256"], str)
        or len(value["policy_sha256"]) != 64
    ):
        raise ValueError("invalid probe policy binding")
    return value


def enabled(workspace: Path) -> bool:
    return settings(workspace) is not None


def install_policy(public: Path, config_path: Path) -> None:
    """Copy the frozen policy next to the bound configuration, checking its pin."""
    cfg = load_yaml(config_path)[0]["runtime_admission"]["probe_policy"]
    source = Path(config_path).parent / POLICY_FILE
    if sha256_file(source) != cfg["policy_sha256"]:
        raise ValueError("unbound probe policy source")
    write_once(Path(public) / POLICY_FILE, source.read_bytes())


def _policy(workspace: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    value = settings(workspace)
    path = Path(workspace) / "public" / POLICY_FILE
    if value is None or not path.is_file() or sha256_file(path) != value["policy_sha256"]:
        raise ValueError("frozen probe policy changed or missing")
    policy = load_json(path)
    if policy.get("profile") != PROFILE or list(policy.get("values", [])) != [3.0, 6.0, 12.0]:
        raise ValueError("unsupported probe policy")
    return value, policy


def _probe_context(validation_rows, base):
    from .federated_model import dependencies
    from .in_round_admission import _model_from_export

    torch = dependencies()[1]
    stacked, keys, n = probe_inputs(validation_rows)
    benign = base["class_names"].index("benign")
    return lambda export: shortcuts(_model_from_export(export, torch=torch), stacked, keys, n, benign, torch)


def _write(path: Path, value: dict[str, Any], create: bool) -> str:
    payload = derived_json_bytes(value)
    if create:
        write_once(path, payload)
    elif not path.is_file() or path.read_bytes() != payload:
        raise ValueError(f"probe derivation replay mismatch: {path.name}")
    return sha256_file(path)


def apply_client_probe(*, workspace, records, base, validation_rows, statistical_state, create):
    """Recompute per-key probe scores on signed updates and fold them into primary decisions."""
    if not enabled(workspace):
        return statistical_state
    workspace = Path(workspace)
    value, policy = _policy(workspace)
    by_client = {str(r["client_id"]): r for r in records}
    clients = sorted(c for c in statistical_state if by_client.get(c, {}).get("bundle") is not None)
    measure = _probe_context(validation_rows, base)
    per = {c: measure(load_json(by_client[c]["submission"] / "update.json")) for c in clients}
    scales = scale_table(policy["client"]["scales"], float(policy["client"]["floor"]))
    multiplier = float(policy["client"]["multiplier"])
    scores = client_scores(per, scales) if clients else {}
    result = {
        "profile": PROFILE,
        "mode": value["mode"],
        "policy_sha256": value["policy_sha256"],
        "base_model_sha256": sha256_file(workspace / "public/base-model.json"),
        "bundles": {c: by_client[c]["bundle_sha256"] for c in clients},
        "multiplier": multiplier,
        "scores": {c: {"score": s, "key": k, "flagged": s > multiplier} for c, (s, k) in scores.items()},
        "attack_labels_used": False,
    }
    pin = _write(workspace / CLIENT_RESULT, result, create)
    if value["mode"] != "enforce":
        return statistical_state
    for c, (s, k) in scores.items():
        state = statistical_state[c]
        if s <= multiplier or not state["primary"].contributes:
            continue
        primary = AdmissionPolicyDecision(
            policy="probe_keynorm",
            status="statistically_quarantined",
            contributes=False,
            score=1.0,
            threshold=None,
            reasons=[
                f"shortcut: feature {k[0]} at {k[1]:g} std units exceeds {multiplier:g}x its clean peer-relative maximum",
                f"probe-score:{s!r}",
                f"probe-gate-result-sha256:{pin}",
            ],
        )
        state["policies"] = [*state["policies"], primary]
        state["primary"] = primary
    return statistical_state


def apply_rollback(*, workspace, base, candidate, validation_rows, create):
    """Return the checkpoint model: the candidate, or the previous global model on alarm."""
    if not enabled(workspace):
        return candidate
    workspace = Path(workspace)
    value, policy = _policy(workspace)
    g = policy["global"]
    if workspace.name == "round-001" and sha256_file(workspace / "public/base-model.json") != g["initial_model_sha256"]:
        raise ValueError("probe policy initial model differs from the campaign starting model")
    measure = _probe_context(validation_rows, base)
    scales = scale_table(g["scales"], float(g["floor"]))
    initial = {(int(j), float(v)): float(x) for j, v, x in g["initial_shortcuts"]}
    score, key = drift_score(measure(candidate), initial, scales)
    alarm = score > float(g["multiplier"]) and value["mode"] in ("enforce", "rollback_only")
    candidate_sha = sha256_bytes(derived_json_bytes(candidate))
    if alarm:
        target = workspace / REJECTED
        payload = derived_json_bytes(candidate)
        if create:
            write_once(target, payload)
        elif not target.is_file() or target.read_bytes() != payload:
            raise ValueError("rejected candidate replay mismatch")
    result = {
        "profile": PROFILE,
        "mode": value["mode"],
        "policy_sha256": value["policy_sha256"],
        "base_model_sha256": sha256_file(workspace / "public/base-model.json"),
        "initial_model_sha256": g["initial_model_sha256"],
        "candidate_sha256": candidate_sha,
        "rejected_candidate_file_sha256": sha256_file(workspace / REJECTED) if alarm else None,
        "score": score,
        "key": key,
        "multiplier": float(g["multiplier"]),
        "rollback": alarm,
    }
    _write(workspace / ROLLBACK_RESULT, result, create)
    return copy.deepcopy(base) if alarm else candidate


def rolled_back(workspace: Path) -> bool:
    path = Path(workspace) / ROLLBACK_RESULT
    return enabled(workspace) and path.is_file() and bool(load_json(path)["rollback"])
