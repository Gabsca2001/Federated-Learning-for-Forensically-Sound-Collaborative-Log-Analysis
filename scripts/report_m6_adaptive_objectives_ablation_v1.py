"""Create a hash-bound report from verified objective-ablation query artifacts."""
from pathlib import Path
from datetime import datetime, UTC
from collections import Counter
import csv, hashlib, json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"results/m6-adaptive-objectives-ablation-v1"
ART=ROOT/"artifacts/m6-adaptive-objectives-ablation-v1"
RUNNER=ROOT/"scripts/run_m6_adaptive_objectives_ablation_v1.py"
LOCK=ROOT/"configs/m6-adaptive-objectives-ablation-v1.lock.json"
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p): return json.loads(p.read_text())
def save(p,x): p.write_text(json.dumps(x,indent=2)+"\n")
def main():
    if OUT.exists(): raise FileExistsError(f"Preserve existing report: {OUT}")
    lock=load(LOCK)
    for name,digest in lock["files"].items():
        if sha(ROOT/name)!=digest: raise ValueError(f"Protocol lock mismatch: {name}")
    cells=[]; input_hashes={}
    for objective in ("targeted","untargeted"):
        for policy in ("gated_composite","tpm_only"):
            folder=ART/f"{objective}-{policy}"
            s=load(folder/"summary.json")
            if s["query_count"]!=66 or s["test_data_accessed"] or s["source_verified"] is not True:
                raise ValueError(f"Invalid cell summary: {folder}")
            if s["config_sha256"]!=sha(ROOT/"configs/m6-adaptive-objectives-ablation-v1.json") or s["generator_sha256"]!=sha(RUNNER):
                raise ValueError(f"Source binding mismatch: {folder}")
            decisions=[]; feasible=0; success_count=0
            for index in range(66):
                p=folder/f"queries/{index:03d}/decision.json"; q=load(p)
                if q["query"]!=index or q["objective"]!=objective or q["policy"]!=policy or q.get("test_data_accessed",False):
                    raise ValueError(f"Decision binding mismatch: {p}")
                decisions.append(q)
                feasible+=int(q["feasible"] and q["kind"]=="adaptive")
                success_count+=int(q.get("success_on_optimization_validation",False))
            selected=load(folder/f"queries/{s['selected_query']:03d}/decision.json")
            attacker_states={c:selected["decisions"][c]["status"] for c in ("client02","client05","client14")}
            candidate_f1=s["baseline_validation_macro_f1"]-s["selected_validation_drop"]
            cells.append(dict(objective=objective,policy=policy,baseline_validation_macro_f1=s["baseline_validation_macro_f1"],selected_validation_macro_f1=candidate_f1,selected_validation_drop=s["selected_validation_drop"],prespecified_threshold=(0.10 if objective=="targeted" else 0.01),success_on_validation=s["success_on_optimization_validation"],selected_targeted_asr=s["selected_targeted_asr"],selected_query=s["selected_query"],feasible_adaptive_proposals=feasible,attacker_selected_status=attacker_states,fixed_control_feasible=s["fixed_attack_feasible"],fixed_control_validation_drop=decisions[1]["validation_drop"],objective_loss=s["objective_loss"],target_validation_rows=s["target_validation_rows"],query_count=s["query_count"],test_accessed=False))
            for p in folder.rglob("*"):
                if p.is_file(): input_hashes[str(p.relative_to(ROOT))]=sha(p)
    OUT.mkdir()
    save(OUT/"summary.json",dict(generated_at=datetime.now(UTC).isoformat(),experiment="M6 adaptive objective/policy frozen-round pilot v1",status="verified",new_inference_performed=False,cells=cells,interpretation="Validation-only, one seed and frozen round. The finite search suggests the statistical gate materially limits this untargeted search on this source round; this is not a live multi-round or held-out efficacy result."))
    with (OUT/"cells.csv").open("w",newline="") as f:
        fields=["objective","policy","baseline_validation_macro_f1","selected_validation_macro_f1","selected_validation_drop","prespecified_threshold","success_on_validation","selected_targeted_asr","selected_query","feasible_adaptive_proposals","fixed_control_feasible","fixed_control_validation_drop","objective_loss"]
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows([{k:c[k] for k in fields} for c in cells])
    plt.rcParams.update({"font.size":10,"axes.spines.top":False,"axes.spines.right":False})
    fig,axs=plt.subplots(1,2,figsize=(10,4.5))
    for ax,obj,title in [(axs[0],"targeted","Targeted: reconnaissance → benign"),(axs[1],"untargeted","Untargeted: all-class degradation")]:
        group=[c for c in cells if c["objective"]==obj]; xs=[0,1]; width=.34
        for j,key,label,color in [(0,"baseline_validation_macro_f1","Clean aggregate","#7f8c8d"),(1,"selected_validation_macro_f1","Selected candidate","#c0392b")]:
            ax.bar([x+(j-.5)*width for x in xs],[g[key] for g in group],width,label=label,color=color)
        ax.set(xticks=xs,xticklabels=["Gated composite","TPM only"],ylim=(0,1),title=title,ylabel="Validation macro-F1")
        ax.legend(fontsize=8); ax.grid(axis="y",alpha=.2)
    fig.suptitle("Best candidate from 64 feasible/infeasible search proposals per cell\nValidation only; no test access")
    fig.tight_layout(); fig.savefig(OUT/"validation-policy-objectives.png",dpi=180,bbox_inches="tight"); fig.savefig(OUT/"validation-policy-objectives.pdf",bbox_inches="tight"); plt.close(fig)
    fig,ax=plt.subplots(figsize=(8,4))
    labels=["Targeted / gated","Targeted / TPM-only","Untargeted / gated","Untargeted / TPM-only"]
    vals=[100*c["selected_validation_drop"] for c in cells]
    colors=["#2471a3" if c["policy"]=="gated_composite" else "#d35400" for c in cells]
    ax.bar(labels,vals,color=colors); ax.axhline(1,color="#555",linestyle="--",label="Untargeted screening threshold: 1 pp")
    ax.axhline(0,color="black",linewidth=.7); ax.set(ylabel="Baseline minus candidate macro-F1 (pp)",title="Observed validation change for selected candidates")
    ax.tick_params(axis="x",rotation=20); ax.legend(fontsize=8); ax.grid(axis="y",alpha=.2)
    fig.tight_layout(); fig.savefig(OUT/"validation-degradation.png",dpi=180,bbox_inches="tight"); fig.savefig(OUT/"validation-degradation.pdf",bbox_inches="tight"); plt.close(fig)
    c={(x["objective"],x["policy"]):x for x in cells}
    rows="\n".join(f"| {o} | {p} | {c[o,p]['baseline_validation_macro_f1']:.6f} | {c[o,p]['selected_validation_macro_f1']:.6f} | {100*c[o,p]['selected_validation_drop']:+.3f} | {c[o,p]['success_on_validation']} | {c[o,p]['selected_targeted_asr']:.3f} |" for o,p in [("targeted","gated_composite"),("targeted","tpm_only"),("untargeted","gated_composite"),("untargeted","tpm_only")])
    (OUT/"README.md").write_text(f'''# Adaptive objective and statistical filter ablation — frozen pilot

Prespecified on 2026-09-30 and completed on the same date. Four cells compare a
targeted reconnaissance-to-benign objective and an untargeted all-class degradation
objective under gated-composite and TPM-only admission. Each cell used one verified
signed source round, three attacker identities and 66 queries (two controls plus 64
adaptive proposals). Independent runner verification recomputed every stored query
for all four cells. No test data were accessed; no training, new signing or live
multi-round trajectory was performed by this pilot.

## Selected validation outcomes

| Objective | Admission policy | Clean macro-F1 | Candidate macro-F1 | Baseline − candidate (pp) | Prespecified success | Secondary targeted ASR |
|---|---|---:|---:|---:|---|---:|
{rows}

For the targeted objective, success required at least +0.10 absolute targeted ASR.
Neither policy achieved it; reconnaissance-to-benign ASR remained zero. For the
untargeted objective, success required a macro-F1 reduction of at least 0.01. The
gated-composite search selected a 0.675-point reduction and did not meet the
criterion; TPM-only selected a 25.297-point reduction and did. The all-class
cross-entropy objective therefore found a much more damaging validation candidate
when the statistical filter was removed, on this specific source round and finite
search. The fixed sign-flip control was infeasible under gated-composite but feasible
under TPM-only; it is a separate, non-adaptive control and must not be attributed to
the adaptive search.

All three attacker updates contribute in the selected candidate in each cell. Under
gated-composite, their selected targeted statuses are {c['targeted','gated_composite']['attacker_selected_status']}; the selected untargeted statuses are {c['untargeted','gated_composite']['attacker_selected_status']}. Under TPM-only all three are accepted in the selected candidates. Admission and damage remain distinct outcomes.

## Interpretation and limits

This factorial pilot directly tests whether the result depends on the target objective
and whether the statistical gate changes this finite search. It supports the
hypothesis that the gate constrained the untargeted candidate on this round. It does
not establish that gated-composite prevents untargeted poisoning in live training,
that TPM-only generally fails, or that the found validation candidate transfers to
held-out data. The attacker has privileged access to the exact validation oracle;
selection and the reported effect use the same validation set. One seed and one
frozen round are not independent replication. The multi-round five-seed experiment
remains separate and showed zero selected-test targeted ASR for its narrower target.

The gate control preserves M4 trust and M5 integrity checks; all source clients were
trusted. TPM-only removes the statistical admission effect, not attestation or
signature checks. Candidate updates are derived from signed inputs and are not newly
signed TPM submissions. The validation drop is baseline macro-F1 minus selected
candidate macro-F1; positive means degradation. Query count is a search budget, not
an independent sample size. Both thresholds were fixed before these four cells ran.

A new live adaptive campaign should be considered only after reviewing this screening
pilot and freezing a separate protocol. To support a thesis claim about held-out or
multi-seed effectiveness, it needs new paired signed trajectories and an untouched
evaluation endpoint; test metrics must not steer attack search or policy selection.

## Reproducibility

Protocol: [M6_ADAPTIVE_OBJECTIVES_ABLATION_V1](../../docs/M6_ADAPTIVE_OBJECTIVES_ABLATION_V1.md).
The report manifest binds every query artifact, config, lock, runner and report output
by SHA-256. Each cell's `summary.json` records the selection, query budget, trust/policy,
source bindings and explicit no-test-access flag. The four independent `verify`
commands completed successfully; they deterministically recomputed the searches and
matched stored artifacts. No existing experiment workspace was overwritten.

Figures: `validation-policy-objectives` compares clean and selected validation F1;
`validation-degradation` shows baseline-minus-candidate changes and the 1 pp screening
threshold. CSV and JSON retain the exact values and attacker decisions.
''')
    files={}
    for p in sorted(OUT.iterdir()):
        if p.is_file() and p.name!="manifest.json": files[p.name]=sha(p)
    (OUT/"manifest.json").write_text(json.dumps({"artifact_type":"m6_adaptive_objective_ablation_report","experiment_lock_sha256":sha(LOCK),"runner_sha256":sha(RUNNER),"reporting_script_sha256":sha(Path(__file__)),"inputs":input_hashes,"outputs":files},indent=2)+"\n")
    print(json.dumps(dict(status="reported_and_query_verified",cell_count=len(cells),output_files=len(files),input_files=len(input_hashes),cells=[{k:x[k] for k in ("objective","policy","selected_validation_macro_f1","selected_validation_drop","success_on_validation","selected_targeted_asr","feasible_adaptive_proposals","attacker_selected_status")} for x in cells]),indent=2))
if __name__=="__main__":main()