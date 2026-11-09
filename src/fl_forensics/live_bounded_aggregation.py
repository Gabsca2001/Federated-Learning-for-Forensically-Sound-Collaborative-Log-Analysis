"""Explicit live containment profile over authenticated original bundles."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import numpy as np

from .bounded_aggregation import aggregate_bounded, digest
from .canonical import sha256_file
from .config import load_yaml
from .federated_model import arrays_from_export
from .preprocessing import derived_json_bytes
from .storage import load_json, write_once

PROFILE = "live-client-envelope-bounded-v1"
ROBUST_PROFILE = "live-client-envelope-robust-bounded-v1"


def enabled(workspace):
    path = Path(workspace) / "public/in-round-admission.yaml"
    if not path.exists():
        return False
    return (
        load_yaml(path)[0].get("runtime_admission", {}).get("observable_policy", {}).get("profile")
        in (PROFILE, ROBUST_PROFILE)
    )


def robust_enabled(workspace):
    path = Path(workspace) / "public/in-round-admission.yaml"
    return path.exists() and load_yaml(path)[0].get("runtime_admission", {}).get("observable_policy", {}).get("profile") == ROBUST_PROFILE


def _operator(workspace):
    if robust_enabled(workspace):
        from .robust_bounded_aggregation import aggregate_robust_bounded
        return aggregate_robust_bounded
    return aggregate_bounded


def reference(workspace):
    from .live_envelope import settings, verify_assets

    public = Path(workspace) / "public"
    value = settings(public / "in-round-admission.yaml")
    paths = verify_assets(public, value)
    cap = load_json(paths["bounds.json"])
    base = arrays_from_export(load_json(public / "base-model.json"), np=np)
    if (
        cap.get("profile") != "clean-common-tensor-l2-cap-v1"
        or cap["cohort_id"] != sha256_file(public / "partition-manifest.json")
        or cap["sizes"] != [a.size for a in base]
    ):
        raise ValueError("bounded aggregation reference/cohort mismatch")
    if value["mode"] != "enforce":
        raise ValueError("bounded live profile requires enforced admission")
    return base, cap


def backend(workspace, fallback):
    if not enabled(workspace):
        return fallback
    base, cap = reference(workspace)

    def bounded_backend(updates):
        indexed = {f"{i:06d}": a for i, (a, w) in enumerate(updates)}
        model, _ = _operator(workspace)(
            base,
            indexed,
            masses={f"{i:06d}": str(w) for i, (a, w) in enumerate(updates)},
            mandatory_gates=dict.fromkeys(indexed, True),
            limits=cap["limits"],
            reference_digest=digest(cap),
            minimum_contributors=1,
        )
        if model is None:
            raise ValueError("no bounded aggregate")
        return model

    bounded_backend.forensic_profile = {
        "transformation": ("float64 tensor-capped deltas, finite smoothed geometric-median convex reweighting, final checkpoint dtype cast" if robust_enabled(workspace) else "float64 per-tensor capped original deltas, then weighted sum, final checkpoint dtype cast"),
        "bounds_sha256": sha256_file(Path(workspace) / "public/observable-assets/bounds.json"),
        "base_model_sha256": sha256_file(Path(workspace) / "public/base-model.json"),
    }
    return bounded_backend


def label(workspace, contract):
    if robust_enabled(workspace):
        return "RobustBoundedDelta-GeometricMedian-observable-envelope"
    return (
        "BoundedDelta-FedAvg-observable-envelope"
        if enabled(workspace)
        else "FedAvg-" + contract.core.primary_policy.replace("_", "-")
    )


def materialize(workspace, records, decisions, create):
    if not enabled(workspace):
        return
    base, cap = reference(workspace)
    by_client = {r["client_id"]: r for r in records}
    models = {
        c: arrays_from_export(load_json(r["submission"] / "update.json"), np=np)
        for c, r in by_client.items()
    }
    masses = {d.core.client_id: d.core.effective_weight_decimal for d, p in decisions}
    gates = {
        d.core.client_id: all(check.passed for check in d.core.m5_checks) for d, p in decisions
    }
    for d, p in decisions:
        if Decimal(d.core.effective_weight_decimal) > 0 and Decimal(
            d.core.effective_weight_decimal
        ) != Decimal(d.core.num_examples):
            raise ValueError("bounded observable profile requires integral example-count mass")
    parameters, report = _operator(workspace)(
        base,
        models,
        masses=masses,
        mandatory_gates=gates,
        limits=cap["limits"],
        reference_digest=digest(cap),
        minimum_contributors=load_json(Path(workspace) / "public/in-round-admission-contract.json")[
            "core"
        ]["minimum_contributors"],
    )
    if parameters is None:
        raise ValueError("bounded derivation lacks quorum")
    ordered = [(models[c], float(masses[c])) for c in sorted(models) if Decimal(masses[c]) > 0]
    runtime = backend(workspace, None)(ordered)
    if not all(np.array_equal(a, b) for a, b in zip(parameters, runtime, strict=True)):
        raise ValueError("bounded report and runtime accumulation order disagree")
    value = {
        "profile": ROBUST_PROFILE if robust_enabled(workspace) else PROFILE,
        "bounded": report,
        "source_bundles": {c: r["bundle_sha256"] for c, r in by_client.items()},
        "source_updates": {c: r["bundle"].core.update_sha256 for c, r in by_client.items()},
        "origin_semantics": "original TPM signatures retained on original bundles; derived float64 deltas are authenticated by the coordinator derivation manifest, not re-signed by clients",
    }
    path = Path(workspace) / "bounded-update-derivation.json"
    payload = derived_json_bytes(value)
    if create:
        write_once(path, payload)
    elif path.read_bytes() != payload:
        raise ValueError("bounded update derivation replay mismatch")
