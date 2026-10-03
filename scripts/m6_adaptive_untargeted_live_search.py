"""Live validation-only untargeted adaptive search for the M6 paired campaign."""
import copy
import hashlib
import json
from pathlib import Path

import numpy as np

from fl_forensics.byzantine import model_delta, update_indicators
from fl_forensics.composite_admission import (
    decide_admission_policies,
    score_statistical_indicators,
    trust_signal_from_checks,
)
from fl_forensics.composite_admission_models import TrustSignal
from fl_forensics.federated_model import arrays_from_export, dependencies, fedavg
from fl_forensics.in_round_admission import (
    _attestation_status,
    _load_bound_contract,
    _load_validation_rows,
    _model_from_export,
    _validation_f1,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import _admission_checks, _load_context
from fl_forensics.secure_round_models import UpdateBundle


def _read(path):
    return json.loads(path.read_text())


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _project(proposed, original, radius):
    delta = [a.astype(np.float64) - b.astype(np.float64)
             for a, b in zip(proposed, original, strict=True)]
    norm = float(np.sqrt(sum(float(np.square(a).sum()) for a in delta)))
    scale = min(1.0, radius / max(norm, 1e-30))
    return [(b + scale * d).astype(b.dtype)
            for b, d in zip(original, delta, strict=True)]


def _export_like(template, arrays):
    value = copy.deepcopy(template)
    for parameter, array in zip(value["parameters"], arrays, strict=True):
        parameter["values"] = np.asarray(array, dtype=parameter["dtype"]).tolist()
    return value


def _validation_rows(source, validation, policy):
    partition = _read(source / "public" / "partition-manifest.json")
    record = partition["server_evaluation_splits"]["validation"]
    if _sha(validation) != record["sha256"]:
        raise ValueError("Validation split differs from signed partition manifest")
    snapshot = _read(validation)
    rows = snapshot.get("rows", {}).get("validation")
    if (snapshot.get("split") != "validation"
            or snapshot.get("class_names") != partition.get("class_names")
            or not isinstance(rows, list)
            or len(rows) != record["row_count"]):
        raise ValueError("Validation split shape/class contract mismatch")
    if policy == "gated_composite":
        contract = _load_bound_contract(source)
        rows = _load_validation_rows(
            workspace=source, validation_split_path=validation, contract=contract
        )
        return contract, rows
    if policy != "tpm_only":
        raise ValueError(f"Unsupported admission policy: {policy}")
    return None, rows


def _rank(query):
    return (-query["validation_macro_f1"],
            query["validation_cross_entropy"],
            -query["query"])


def _selected(queries):
    eligible = [item for item in queries
                if item["kind"] == "adaptive" and item["feasible"]]
    return max(eligible, key=_rank) if eligible else None


def execute_live(output, verify, *, source, trust, validation, cfg, evaluation_time):
    """Write or independently recompute the bounded search; never reads test."""
    if cfg.get("test_access") is not False:
        raise ValueError("Test access is forbidden")
    policy = cfg["admission_policy"]
    context = _load_context(source / "public")
    contract, rows = _validation_rows(source, validation, policy)
    base = _read(source / "public" / "base-model.json")
    ids = sorted(path.name for path in (source / "proposals").iterdir()
                 if path.is_dir())
    if len(ids) != 15 or not set(cfg["attackers"]) <= set(ids):
        raise ValueError("Expected 15 client proposals and all declared attackers")
    originals = {cid: _read(source / "proposals" / cid / "update.json")
                 for cid in ids}
    original_arrays = {cid: arrays_from_export(originals[cid], np=np)
                       for cid in ids}
    original_decisions = {}
    for cid in ids:
        proposal = source / "proposals" / cid
        bundle = UpdateBundle.model_validate(_read(proposal / "bundle.json"))
        checks = _admission_checks(
            bundle=bundle, submission=proposal, context=context, base=base,
            trust_workspace=trust, now=evaluation_time, expected_client_id=cid,
        )
        if not all(check.passed for check in checks):
            raise ValueError(f"Original proposal failed M4/M5 verification: {cid}")
        original_decisions[cid] = {
            "num_examples": bundle.core.num_examples,
            "checks": [check.model_dump(mode="json") for check in checks],
        }
        if policy == "gated_composite":
            original_decisions[cid]["trust"] = trust_signal_from_checks(
                original_decisions[cid]["checks"],
                raw_status=_attestation_status(trust, bundle),
                passed_with_warning_risk=contract.core.passed_with_warning_risk,
            ).model_dump(mode="json")

    _, torch, _, _, aggregate, *_ = dependencies()
    torch.set_num_threads(1)
    batch_size = 128
    base_f1 = _validation_f1(model_export=base, rows=rows, batch_size=batch_size)
    baseline_f1 = None
    features = torch.tensor([row["features"] for row in rows], dtype=torch.float32)
    class_to_index = {name: index for index, name in enumerate(base["class_names"])}
    labels = torch.tensor(
        [class_to_index[row["label"]] for row in rows], dtype=torch.long
    )

    def validation_metrics(model_export, gradient=False):
        model = _model_from_export(model_export, torch=torch)
        model.eval()
        if not gradient:
            with torch.no_grad():
                logits = model(features)
                loss = torch.nn.functional.cross_entropy(logits, labels)
                ce = float(loss.item())
            return ce, None
        logits = model(features)
        loss = torch.nn.functional.cross_entropy(logits, labels)
        loss.backward()
        direction = [parameter.grad.detach().numpy().copy()
                     for parameter in model.parameters()
                     if parameter.grad is not None]
        if len(direction) != len(list(model.parameters())):
            raise ValueError("Missing gradient for one or more model parameters")
        norm = float(np.sqrt(sum(
            float(np.square(item.astype(np.float64)).sum()) for item in direction
        )))
        if not np.isfinite(norm) or norm == 0.0:
            raise ValueError("Invalid untargeted attack gradient")
        return float(loss.detach().item()), [item / norm for item in direction]

    thresholds = contract.core.thresholds if contract else None
    refs = ({reference.name: reference
             for reference in contract.core.indicator_references}
            if contract else {})
    queries = []
    expected_files = set()

    def persist(relative, value):
        path = output / relative
        expected_files.add(str(relative))
        data = derived_json_bytes(value)
        if verify:
            if path.read_bytes() != data:
                raise ValueError(f"Recomputation mismatch: {path}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(data)

    clean_f1 = {}
    for cid in ids:
        clean_f1[cid] = _validation_f1(
            model_export=originals[cid], rows=rows, batch_size=batch_size
        )

    def query(models, kind, parent=None, radius=None, step=None):
        nonlocal baseline_f1
        deltas = [
            model_delta(arrays_from_export(base, np=np),
                        arrays_from_export(models[cid], np=np))
            for cid in ids
        ]
        indicators = update_indicators(deltas, client_ids=ids)
        if policy == "gated_composite":
            for cid, indicator in zip(ids, indicators, strict=True):
                score = (clean_f1[cid] if kind == "clean_control"
                         or cid not in cfg["attackers"]
                         else _validation_f1(
                             model_export=models[cid], rows=rows,
                             batch_size=batch_size))
                indicator["validation_macro_f1"] = score
                indicator["validation_impact"] = base_f1 - score
            signals = score_statistical_indicators(
                indicators, references=refs,
                weights=contract.core.indicator_weights,
                z_cap=contract.core.robust_z_cap,
            )
        else:
            signals = None

        decisions = {}
        weighted = []
        for cid in ids:
            if policy == "gated_composite":
                decision = next(
                    item for item in decide_admission_policies(
                        trust=TrustSignal.model_validate(
                            original_decisions[cid]["trust"]),
                        statistics=signals[cid],
                        statistical_threshold=thresholds.statistical_threshold,
                        composite_threshold=thresholds.composite_threshold,
                        composite_downweight_threshold=(
                            thresholds.composite_downweight_threshold),
                        trust_weight=thresholds.trust_weight,
                    ) if item.policy == "gated_composite"
                )
                decisions[cid] = decision.model_dump(mode="json")
                factor = (1.0 if decision.status == "accepted"
                          else contract.core.accepted_downweight_factor
                          if decision.status == "accepted_downweighted" else 0.0)
            else:
                decisions[cid] = {
                    "policy": "tpm_only", "status": "accepted",
                    "contributes": True,
                    "reasons": ["M4/M5 identity, attestation and signed bundle verified"],
                }
                factor = 1.0
            if factor:
                weighted.append((
                    arrays_from_export(models[cid], np=np),
                    original_decisions[cid]["num_examples"] * factor,
                ))

        minimum = contract.core.minimum_contributors if contract else len(ids)
        enough = len(weighted) >= minimum
        averaged = (_export_like(base, fedavg(weighted, aggregate=aggregate))
                    if enough else None)
        aggregate_f1 = (_validation_f1(
            model_export=averaged, rows=rows, batch_size=batch_size
        ) if averaged else None)
        aggregate_ce = (validation_metrics(averaged)[0] if averaged else None)
        if kind == "clean_control":
            baseline_f1 = aggregate_f1
        feasible = (enough and all(
            decisions[cid]["contributes"] for cid in cfg["attackers"]
        ))
        value = {
            "query": len(queries), "kind": kind, "parent_query": parent,
            "radius": radius, "step": step, "admission_policy": policy,
            "feasible": feasible, "contributor_count": len(weighted),
            "validation_macro_f1": aggregate_f1,
            "validation_cross_entropy": aggregate_ce,
            "validation_drop": (None if aggregate_f1 is None
                                else baseline_f1 - aggregate_f1),
            "statistical_filter_applied": policy == "gated_composite",
            "decisions": decisions,
            "statistics": ({cid: signals[cid].model_dump(mode="json")
                            for cid in ids} if signals else None),
            "candidate_sha256": {
                cid: hashlib.sha256(derived_json_bytes(models[cid])).hexdigest()
                for cid in cfg["attackers"]
            },
        }
        number = len(queries)
        for cid in cfg["attackers"]:
            persist(Path(f"queries/{number:03d}/{cid}.json"), models[cid])
        if averaged is not None:
            persist(Path(f"queries/{number:03d}/aggregate.json"), averaged)
        persist(Path(f"queries/{number:03d}/decision.json"), value)
        queries.append(value)
        print(
            f"query {number + 1}/{cfg['max_queries']}: {kind}, "
            f"policy={policy}, feasible={feasible}, "
            f"validation_macro_f1={aggregate_f1}, validation_drop={value['validation_drop']}",
            flush=True,
        )
        return value, averaged

    clean, clean_aggregate = query(dict(originals), "clean_control")
    if not verify and len(expected_files) == 0 and (output / "summary.json").exists():
        raise FileExistsError(f"Search output already exists: {output}")
    controls = dict(originals)
    base_arrays = arrays_from_export(base, np=np)
    for cid in cfg["attackers"]:
        controls[cid] = _export_like(
            base, [b - 15 * (u - b) for b, u in zip(
                base_arrays, original_arrays[cid], strict=True)]
        )
    fixed, _ = query(controls, "fixed_signflip_control")
    norms = {
        cid: float(np.sqrt(sum(
            float(np.square((u - b).astype(np.float64)).sum())
            for b, u in zip(base_arrays, original_arrays[cid], strict=True)
        ))) for cid in cfg["attackers"]
    }

    for radius in cfg["radii"]:
        current = dict(originals)
        current_aggregate = clean_aggregate
        current_query = clean
        step = cfg["initial_step"]
        for _ in range(cfg["steps_per_radius"]):
            _, direction = validation_metrics(current_aggregate, gradient=True)
            proposal = dict(originals)
            for cid in cfg["attackers"]:
                arrays = arrays_from_export(current[cid], np=np)
                proposed = [array + step * norms[cid] * gradient
                            for array, gradient in zip(arrays, direction, strict=True)]
                projected = _project(
                    proposed, original_arrays[cid], radius * norms[cid]
                )
                proposal[cid] = _export_like(base, projected)
            candidate, model = query(
                proposal, "adaptive", current_query["query"], radius, step
            )
            if candidate["feasible"] and _rank(candidate) > _rank(current_query):
                current, current_aggregate, current_query = proposal, model, candidate
                step = min(radius, step * cfg["step_growth"])
            else:
                step = max(cfg["minimum_step"], step * cfg["step_shrink"])

    if len(queries) != cfg["max_queries"]:
        raise ValueError("Adaptive query budget mismatch")
    chosen = _selected(queries)
    drop = None if chosen is None else clean["validation_macro_f1"] - chosen["validation_macro_f1"]
    success = (chosen is not None and
               drop >= cfg["minimum_validation_macro_f1_drop"])
    summary = {
        "experiment_id": cfg["experiment_id"],
        "admission_policy": policy,
        "objective": cfg["objective"],
        "config_sha256": hashlib.sha256(derived_json_bytes(cfg)).hexdigest(),
        "generator_sha256": _sha(Path(__file__)),
        "source_bindings": {
            str(path.relative_to(source)): _sha(path)
            for path in sorted((source / "proposals").rglob("*.json"))
        },
        "source_verified": True,
        "clean_control_computed": True,
        "test_data_accessed": False,
        "query_count": len(queries),
        "validation_row_count": len(rows),
        "baseline_validation_macro_f1": clean["validation_macro_f1"],
        "baseline_validation_cross_entropy": clean["validation_cross_entropy"],
        "fixed_control_feasible": fixed["feasible"],
        "fixed_control_validation_drop": fixed["validation_drop"],
        "selected_query": None if chosen is None else chosen["query"],
        "selected_validation_macro_f1": (
            None if chosen is None else chosen["validation_macro_f1"]),
        "selected_validation_cross_entropy": (
            None if chosen is None else chosen["validation_cross_entropy"]),
        "selected_validation_drop": drop,
        "success_on_optimization_validation": success,
        "selection_rule": cfg["selection"],
        "semantics": cfg["artifact_semantics"],
        "knowledge": cfg["knowledge"],
    }
    persist(Path("summary.json"), summary)
    if verify:
        actual = {str(path.relative_to(output)) for path in output.rglob("*.json")}
        if actual != expected_files:
            raise ValueError("Unexpected or missing search JSON artifacts")
    print(json.dumps({"status": "verified" if verify else "searched", **summary},
                     indent=2), flush=True)
    return summary
