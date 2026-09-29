"""Live proposal search, before aggregation; same bounded algorithm as frozen pilot."""
import argparse
import copy
import hashlib
import json
import platform
from importlib.metadata import version
from pathlib import Path
import numpy as np
from fl_forensics.byzantine import model_delta, update_indicators
from fl_forensics.composite_admission import score_statistical_indicators, decide_admission_policies
from fl_forensics.composite_admission_models import TrustSignal
from fl_forensics.federated_model import arrays_from_export, dependencies, fedavg
from fl_forensics.in_round_admission import (
    verify_in_round_secure_round, _load_bound_contract, _load_validation_rows,
    _validation_f1, _model_from_export,
)
from fl_forensics.preprocessing import derived_json_bytes

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/m6-adaptive-frozen-pilot-v1.json"

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def read(p):
    return json.loads(p.read_text())

def rank_query(query):
    return (query["targeted_asr"], -query["targeted_loss"], -query["query"])

def selected_query(queries):
    eligible = [q for q in queries if q["feasible"] and q["kind"] == "adaptive"]
    return max(eligible, key=rank_query) if eligible else None

def project_arrays(proposed, original, radius):
    differences = [a.astype(np.float64)-b.astype(np.float64) for a,b in zip(proposed,original,strict=True)]
    norm = float(np.sqrt(sum(float(np.square(a).sum()) for a in differences)))
    scale = min(1., radius/max(norm,1e-30))
    return [(b+scale*d).astype(b.dtype) for b,d in zip(original,differences,strict=True)]

def export_like(template, arrays):
    value = copy.deepcopy(template)
    for parameter, array in zip(value["parameters"], arrays, strict=True):
        parameter["values"] = np.asarray(array, dtype=parameter["dtype"]).tolist()
    return value

def execute_live(output, verify, *, source, trust, validation, cfg, evaluation_time):
    check_only=False
    from fl_forensics.secure_round import _load_context, _admission_checks
    from fl_forensics.secure_round_models import UpdateBundle
    from fl_forensics.in_round_admission import _attestation_status
    from fl_forensics.composite_admission import trust_signal_from_checks
    if cfg["test_access"] is not False:raise ValueError("Test access is forbidden")
    context=_load_context(source/"public")
    contract = _load_bound_contract(source)
    assert contract.core.primary_policy == "gated_composite"
    rows = _load_validation_rows(workspace=source, validation_split_path=validation, contract=contract)
    base = read(source/"public/base-model.json")
    base_arrays = arrays_from_export(base, np=np)
    ids = sorted(p.name for p in (source/"proposals").iterdir() if p.is_dir())
    assert len(ids) == 15 and set(cfg["attackers"]) <= set(ids)
    originals = {cid:read(source/"proposals"/cid/"update.json") for cid in ids}
    original_arrays = {cid:arrays_from_export(originals[cid], np=np) for cid in ids}
    original_decisions={}
    for cid in ids:
        proposal=source/"proposals"/cid
        bundle=UpdateBundle.model_validate(read(proposal/"bundle.json"))
        checks=_admission_checks(bundle=bundle,submission=proposal,context=context,
            base=base,trust_workspace=trust,now=evaluation_time,expected_client_id=cid)
        if not all(c.passed for c in checks):raise ValueError(f"Proposal failed verification: {cid}")
        signal=trust_signal_from_checks([c.model_dump(mode="json") for c in checks],
            raw_status=_attestation_status(trust,bundle),passed_with_warning_risk=contract.core.passed_with_warning_risk)
        original_decisions[cid]={"trust":signal.model_dump(mode="json"),"num_examples":bundle.core.num_examples}
    _, torch, _, _, aggregate, *_ = dependencies()
    torch.set_num_threads(1)
    batch_size = 128
    def f1(model):
        return _validation_f1(model_export=model, rows=rows, batch_size=batch_size)
    base_f1 = f1(base)
    clean_f1 = {cid:f1(originals[cid]) for cid in ids}
    thresholds = contract.core.thresholds
    refs = {r.name:r for r in contract.core.indicator_references}
    queries=[]
    expected_files=set()
    def persist(relative, value):
        data=derived_json_bytes(value); path=output/relative
        expected_files.add(str(relative))
        if check_only:
            return
        if verify:
            if path.read_bytes() != data:
                raise ValueError(f"Recomputation mismatch: {path}")
        else:
            path.parent.mkdir(parents=True,exist_ok=True)
            with path.open("xb") as f:f.write(data)
    target_rows=[r for r in rows if r["label"]==cfg["source_class"]]
    if not target_rows:
        raise ValueError("No source-class validation observations")
    features=torch.tensor([r["features"] for r in target_rows],dtype=torch.float32)
    target_index=base["class_names"].index(cfg["target_class"])
    target_labels=torch.full((len(target_rows),),target_index,dtype=torch.long)
    def target_metrics(model_export, gradient=False):
        model=_model_from_export(model_export,torch=torch)
        model.eval()
        logits=model(features)
        loss=torch.nn.functional.cross_entropy(logits,target_labels)
        asr=float((logits.argmax(dim=1)==target_index).float().mean().item())
        if not gradient:
            return asr,float(loss.detach().item())
        loss.backward()
        direction=[-parameter.grad.detach().numpy().copy() for parameter in model.parameters()]
        norm=float(np.sqrt(sum(float(np.square(d.astype(np.float64)).sum()) for d in direction)))
        if not np.isfinite(norm) or norm==0:
            raise ValueError("Invalid attack gradient")
        return [d/norm for d in direction]
    baseline_f1=None
    def query(models, kind, parent=None, radius=None, step=None):
        nonlocal baseline_f1
        deltas=[model_delta(base_arrays,arrays_from_export(models[cid],np=np)) for cid in ids]
        indicators=update_indicators(deltas,client_ids=ids)
        for cid, indicator in zip(ids,indicators,strict=True):
            score=clean_f1[cid] if kind=="clean_control" or cid not in cfg["attackers"] else f1(models[cid])
            indicator["validation_macro_f1"]=score
            indicator["validation_impact"]=base_f1-score
        signals=score_statistical_indicators(indicators,references=refs,weights=contract.core.indicator_weights,z_cap=contract.core.robust_z_cap)
        decisions={}
        weighted=[]
        for cid in ids:
            decision=next(d for d in decide_admission_policies(trust=TrustSignal.model_validate(original_decisions[cid]["trust"]),statistics=signals[cid],statistical_threshold=thresholds.statistical_threshold,composite_threshold=thresholds.composite_threshold,composite_downweight_threshold=thresholds.composite_downweight_threshold,trust_weight=thresholds.trust_weight) if d.policy=="gated_composite")
            decisions[cid]=decision.model_dump(mode="json")
            factor=1.0 if decision.status=="accepted" else contract.core.accepted_downweight_factor if decision.status=="accepted_downweighted" else 0.0
            if factor:
                weighted.append((arrays_from_export(models[cid],np=np),original_decisions[cid]["num_examples"]*factor))
        enough=len(weighted)>=contract.core.minimum_contributors
        averaged=export_like(base,fedavg(weighted,aggregate=aggregate)) if enough else None
        aggregate_f1=f1(averaged) if averaged else None
        if kind=="clean_control":
            baseline_f1=aggregate_f1
        feasible=enough and all(decisions[cid]["contributes"] for cid in cfg["attackers"])
        target_asr,target_loss=target_metrics(averaged) if averaged else (None,None)
        value=dict(query=len(queries),kind=kind,parent_query=parent,radius=radius,step=step,targeted_asr=target_asr,targeted_loss=target_loss,feasible=feasible,contributor_count=len(weighted),validation_macro_f1=aggregate_f1,validation_drop=None if aggregate_f1 is None else baseline_f1-aggregate_f1,decisions=decisions,statistics={cid:signals[cid].model_dump(mode="json") for cid in ids},candidate_sha256={cid:hashlib.sha256(derived_json_bytes(models[cid])).hexdigest() for cid in cfg["attackers"]})
        number=len(queries)
        for cid in cfg["attackers"]:
            persist(Path(f"queries/{number:03d}/{cid}.json"),models[cid])
        if averaged is not None:
            persist(Path(f"queries/{number:03d}/aggregate.json"),averaged)
        persist(Path(f"queries/{number:03d}/decision.json"),value)
        queries.append(value)
        print(f"query {number+1}/{cfg['max_queries']}: {kind}, feasible={feasible}, targeted_ASR={target_asr}, validation_drop={value['validation_drop']}",flush=True)
        return value, averaged
    clean,clean_aggregate=query(dict(originals),"clean_control")
    if check_only:
        print("Source signatures, policy decisions and clean aggregation verified; no candidate search or output writes.")
        return
    control_models=dict(originals)
    for cid in cfg["attackers"]:
        control_models[cid]=export_like(base,[b-15*(u-b) for b,u in zip(base_arrays,original_arrays[cid],strict=True)])
    fixed,_=query(control_models,"fixed_signflip_control")
    norms={cid:float(np.sqrt(sum(float(np.square((u-b).astype(np.float64)).sum()) for b,u in zip(base_arrays,original_arrays[cid],strict=True)))) for cid in cfg["attackers"]}
    for radius in cfg["radii"]:
        current=dict(originals)
        current_aggregate=clean_aggregate
        current_query=clean
        step=cfg["initial_step"]
        for _iteration in range(cfg["steps_per_radius"]):
            direction=target_metrics(current_aggregate,gradient=True)
            proposal=dict(originals)
            for cid in cfg["attackers"]:
                arrays=arrays_from_export(current[cid],np=np)
                proposed=[a+step*norms[cid]*d for a,d in zip(arrays,direction,strict=True)]
                projected=project_arrays(proposed,original_arrays[cid],radius*norms[cid])
                proposal[cid]=export_like(base,projected)
            candidate,model=query(proposal,"adaptive",current_query["query"],radius,step)
            if candidate["feasible"] and rank_query(candidate)>rank_query(current_query):
                current,current_aggregate,current_query=proposal,model,candidate
                step=min(radius,step*cfg["step_growth"])
            else:
                step=max(cfg["minimum_step"],step*cfg["step_shrink"])
    assert len(queries)==cfg["max_queries"]
    chosen=selected_query(queries)
    gain=None if chosen is None else chosen["targeted_asr"]-clean["targeted_asr"]
    success=chosen is not None and gain>=cfg["minimum_asr_gain"]
    summary=dict(experiment_id=cfg["experiment_id"],config_sha256=hashlib.sha256(derived_json_bytes(cfg)).hexdigest(),generator_sha256=sha(Path(__file__)),source_bindings={str(p.relative_to(source)):sha(p) for p in sorted((source/"proposals").rglob("*.json"))},source_verified=True,clean_control_computed=True,test_data_accessed=False,query_count=len(queries),target_validation_rows=len(target_rows),baseline_targeted_asr=clean["targeted_asr"],baseline_validation_macro_f1=baseline_f1,fixed_attack_feasible=fixed["feasible"],fixed_attack_targeted_asr=fixed["targeted_asr"],selected_query=None if chosen is None else chosen["query"],selected_targeted_asr=None if chosen is None else chosen["targeted_asr"],selected_asr_gain=gain,selected_validation_drop=None if chosen is None else chosen["validation_drop"],success_on_optimization_validation=success,semantics=cfg["artifact_semantics"],knowledge=cfg["knowledge"],selection_rule=cfg["selection"])
    persist(Path("summary.json"),summary)
    if verify:
        if {str(f.relative_to(output)) for f in output.rglob("*.json")} != expected_files:
            raise ValueError("Unexpected or missing JSON artifacts")
    print(json.dumps(dict(status="verified" if verify else "searched",**summary),indent=2))
    return summary
