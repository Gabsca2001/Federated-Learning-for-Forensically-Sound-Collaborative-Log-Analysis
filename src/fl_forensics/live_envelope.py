"""Authenticated, prefix-only adapter for the experimental retreat envelope.

Full verification requires every predecessor round, its submissions and trust
evidence. A signed checkpoint alone cannot substitute for verifying that prefix.
Unsupported observations fail closed; an audit-only arm still enforces trust.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from .canonical import sha256_file
from .client_envelope_policy import ClientEnvelopePolicy
from .composite_admission_models import AdmissionPolicyDecision
from .config import load_yaml
from .federated_model import arrays_from_export
from .preprocessing import derived_json_bytes
from .sequential_decision import digest
from .state_conditioned_audit import load_model, residual_scores
from .storage import load_json, write_once

PROFILE = "live-client-envelope-retreat-v1"
ASSETS = ("conditioned.npz", "state-disabled.npz", "calibration.json", "envelope.json")


def settings(config_path):
    value = load_yaml(config_path)[0].get("runtime_admission", {}).get("observable_policy")
    if not isinstance(value, dict) or set(value) != {"profile", "mode", "assets"}:
        raise ValueError("invalid observable policy binding")
    if value["profile"] not in (PROFILE, "live-client-envelope-bounded-v1", "live-client-envelope-robust-bounded-v1") or value[
        "mode"
    ] not in ("enforce", "audit_only"):
        raise ValueError("unsupported observable policy profile or mode")
    expected_assets = set(ASSETS) | (
        {"bounds.json"} if value["profile"] in ("live-client-envelope-bounded-v1", "live-client-envelope-robust-bounded-v1") else set()
    )
    if set(value["assets"]) != expected_assets:
        raise ValueError("incomplete frozen observable assets")
    for name in value["assets"]:
        pin = value["assets"][name]
        if (
            not isinstance(pin, str)
            or len(pin) != 64
            or any(c not in "0123456789abcdef" for c in pin)
        ):
            raise ValueError("invalid observable asset digest")
    return value


def verify_assets(public, value):
    paths = {name: Path(public) / "observable-assets" / name for name in value["assets"]}
    for name, path in paths.items():
        if sha256_file(path) != value["assets"][name]:
            raise ValueError(f"frozen observable asset changed: {name}")
    return paths


def install_assets(public, config_path):
    value = settings(config_path)
    for name in value["assets"]:
        source = Path(config_path).parent / "observable-assets" / name
        if sha256_file(source) != value["assets"][name]:
            raise ValueError(f"unbound observable source asset: {name}")
        write_once(Path(public) / "observable-assets" / name, source.read_bytes())
    paths = verify_assets(public, value)
    cohort = sha256_file(Path(public) / "partition-manifest.json")
    for view in ("conditioned", "state-disabled"):
        model = load_model(paths[f"{view}.npz"])
        if model["schema"]["cohort_id"] != cohort:
            raise ValueError("frozen detector is not calibrated for this partition")


def _previous_history(workspace, context, contract, trust_workspace, validation_split_path):
    if context.core.round_number == 1:
        return []
    from .in_round_admission import _load_bound_contract, verify_in_round_secure_round

    parent = workspace.parent / f"round-{context.core.round_number - 1:03d}"
    if sha256_file(parent / "checkpoint/manifest.json") != context.core.previous_checkpoint_sha256:
        raise ValueError("observable prefix does not match the signed predecessor")
    previous_contract = _load_bound_contract(parent)
    if previous_contract.core.policy_config_sha256 != contract.core.policy_config_sha256:
        raise ValueError("observable policy changed inside the campaign")
    report = verify_in_round_secure_round(
        workspace=parent,
        trust_workspace=trust_workspace,
        submissions_root=parent / "submissions",
        validation_split_path=validation_split_path,
        client_receipts=parent / "client-receipts",
        require_derivation=True,
    )
    if report["status"] != "verified":
        raise ValueError(f"unverified observable predecessor: {report.get('errors')}")
    previous = load_json(parent / "observable-policy-result.json")
    if len(previous["history"]) != context.core.round_number - 1:
        raise ValueError("incomplete observable history")
    return previous["history"]


def apply_live_envelope(
    *,
    workspace,
    trust_workspace,
    validation_split_path,
    context,
    contract,
    records,
    base,
    statistical_state,
    create,
):
    """Recompute observables from verified signed updates, before signing actions."""
    workspace = Path(workspace)
    from .partition_training_binding import verify_public_partition_training_binding

    verify_public_partition_training_binding(workspace / "public")
    value = settings(workspace / "public/in-round-admission.yaml")
    paths = verify_assets(workspace / "public", value)
    calibration, envelope = load_json(paths["calibration.json"]), load_json(paths["envelope.json"])
    models = {v: load_model(paths[f"{v}.npz"]) for v in ("conditioned", "state-disabled")}
    clients = calibration["clients"]
    if any(
        m["schema"]["cohort_id"] != sha256_file(workspace / "public/partition-manifest.json")
        for m in models.values()
    ):
        raise ValueError("observable cohort changed")
    history = _previous_history(
        workspace, context, contract, trust_workspace, validation_split_path
    )
    by_client = {r["client_id"]: r for r in records}
    if len(by_client) != len(records) or set(by_client) - set(clients):
        raise ValueError("ambiguous observable enrollment roster")
    gates = {
        c: c in statistical_state
        and statistical_state[c]["trust"].admissible
        and c in by_client
        and all(ch.passed for ch in by_client[c]["checks"])
        and by_client[c]["bundle"] is not None
        for c in clients
    }
    masses = {
        c: by_client[c]["bundle"].core.num_examples
        if c in by_client and by_client[c]["bundle"] is not None
        else 0
        for c in clients
    }
    source = {
        "context": context.core_digest,
        "base": sha256_file(workspace / "public/base-model.json"),
        "bundles": {c: by_client[c]["bundle_sha256"] for c in sorted(by_client)},
        "assets": value["assets"],
    }
    source_digest = digest(source)
    risks = {v: [0.0] * len(clients) for v in models}
    distances = {}
    supported = all(gates.values())
    if supported:
        arrays = arrays_from_export(base, np=np)
        flat = lambda a: np.concatenate([x.astype(np.float64).ravel() for x in a])
        local = [
            arrays_from_export(load_json(by_client[c]["submission"] / "update.json"), np=np)
            for c in clients
        ]
        # model_delta uses float64 differences, matching the calibrated observation exporter.
        updates = np.stack(
            [
                flat(
                    [
                        a.astype(np.float64) - b.astype(np.float64)
                        for a, b in zip(items, arrays, strict=True)
                    ]
                )
                for items in local
            ]
        )
        observation = {
            "states": flat(arrays)[None, :],
            "updates": updates[None, :, :],
            "clients": clients,
            "sizes": [a.size for a in arrays],
            "cohort_id": sha256_file(workspace / "public/partition-manifest.json"),
        }
        for view, model in models.items():
            result = residual_scores(observation, model)
            risks[view] = result["risk"][0].tolist()
            distances[view] = float(result["state_support_distance"][0])
            limit = min(
                calibration["state_support_limits"][view], envelope["state_support_limits"][view]
            )
            supported = supported and distances[view] <= limit * (1 + 1e-12) + 1e-12
    frame = {
        "round": context.core.round_number,
        "risk": risks,
        "context_supported": supported,
        "mandatory_gate": gates,
        "masses": masses,
        "source_observation_sha256": source_digest,
    }
    history = [*history, frame]
    policy = ClientEnvelopePolicy(
        calibration, envelope, minimum_contributors=contract.core.minimum_contributors
    )
    for number, prior in enumerate(history, 1):
        if prior["round"] != number:
            raise ValueError("nonconsecutive observable history")
        decision = policy.step(
            number,
            prior["risk"],
            context_supported=prior["context_supported"],
            mandatory_gate=prior["mandatory_gate"],
            masses=prior["masses"],
            expected_previous_digest=policy.head,
            source_observation_sha256=prior["source_observation_sha256"],
        )
    result = {
        "profile": value["profile"],
        "mode": value["mode"],
        "source": source,
        "history": history,
        "state_support_distances": distances,
        "decision": decision,
        "unsupported_context_blocks_checkpoint": True,
        "attack_labels_used": False,
    }
    payload = derived_json_bytes(result)
    target = workspace / "observable-policy-result.json"
    if create:
        write_once(target, payload)
    elif target.read_bytes() != payload:
        raise ValueError("observable policy replay mismatch")
    result_pin = sha256_file(target)
    for client, state in statistical_state.items():
        blocked = not decision["supported"] or (
            value["mode"] == "enforce" and client in decision["quarantine_current_round"]
        )
        status = "statistically_quarantined" if blocked else "accepted"
        if not state["trust"].admissible:
            status = "trust_quarantined"
        reason = (
            "unsupported observable context: no checkpoint"
            if not decision["supported"]
            else (
                "confirmed current envelope evidence"
                if blocked
                else "trust gate passed; current policy permits contribution"
            )
        )
        primary = AdmissionPolicyDecision(
            policy="observable_envelope",
            status=status,
            contributes=status == "accepted",
            score=float(blocked),
            threshold=None,
            reasons=[
                reason,
                f"observable-policy-result-sha256:{result_pin}",
                f"observable-policy-mode:{value['mode']}",
            ],
        )
        state["policies"] = [*state["policies"], primary]
        state["primary"] = primary
    return statistical_state
