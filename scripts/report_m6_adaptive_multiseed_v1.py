"""Consolidate stored M6 paired outcomes, without training or test inference."""
from pathlib import Path
from collections import Counter
import csv, hashlib, json, statistics
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"results/m6-adaptive-multiseed-v1"
SOURCES={}
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):
    SOURCES[str(p.relative_to(ROOT))]=sha(p)
    return json.loads(p.read_text())
def require(ok, message):
    if not ok: raise ValueError(message)
def asr(metrics):
    cm=metrics["confusion_matrix"]
    row=cm["values"][cm["labels"].index("reconnaissance")]
    return row[cm["labels"].index("benign")],sum(row)
def write(name,obj): (OUT/name).write_text(json.dumps(obj,indent=2)+"\n")
def figure(fig,name):
    fig.tight_layout()
    for ext in ("png","pdf"): fig.savefig(OUT/f"{name}.{ext}",dpi=170,bbox_inches="tight")
    plt.close(fig)
def stats(values): return {"n":len(values),"mean":statistics.mean(values),"sample_sd":statistics.stdev(values)}
def main():
    require(not OUT.exists(),"Output already exists: preserve existing report")
    master=read(ROOT/"configs/m6-adaptive-multiseed-v1.lock.json")
    completed=read(ROOT/"artifacts/m6-adaptive-multiseed-v1-complete.json")
    require(completed["status"]=="verified" and completed["lock_sha256"]==sha(ROOT/"configs/m6-adaptive-multiseed-v1.lock.json"),"Extension completion binding")
    for name,digest in master["files"].items(): require(sha(ROOT/name)==digest,name)
    rows=[]; trajectories=[]; decisions=[]; searches=[]
    for seed in [341593,*master["new_seeds"]]:
        pair=ROOT/f"artifacts/m6-adaptive-paired-s{seed}-{'v4' if seed==341593 else 'v1'}"
        receipt=read(pair/"complete.json"); lock=read(pair/"execution-lock.json")
        require(receipt["status"]=="verified" and receipt["execution_lock_sha256"]==sha(pair/"execution-lock.json"),f"Completion {seed}")
        for name,digest in lock["files"].items(): require(sha(ROOT/name)==digest,name)
        attackers=set(lock["attack_config"]["attackers"])
        row={"seed":seed,"cohort":"exploratory reference" if seed==341593 else "prespecified extension"}
        for arm in ("clean","adaptive"):
            w=pair/arm; cm=read(w/"campaign-manifest.json")["core"]
            require(cm["round_count"]==30 and len(cm["rounds"])==30,"Round count")
            ep=w/"evaluation/selected-checkpoint-evaluation.json"; e=read(ep)
            require(sha(ep)==cm["final_evaluation_sha256"],"Final evaluation hash")
            k,n=asr(e["metrics"]["test"]); require(n>0,"Target denominator")
            row.update({f"{arm}_selected_round":e["selected_round"],f"{arm}_test_macro_f1":e["metrics"]["test"]["macro_f1_all_model_classes"],f"{arm}_test_asr":k/n,f"{arm}_target_errors":k,f"{arm}_target_examples":n})
            for rr in cm["rounds"]:
                r=rr["round_number"]; rw=w/f"rounds/round-{r:03d}"
                cp=read(rw/"checkpoint/manifest.json")["core"]
                require(sha(rw/"checkpoint/manifest.json")==rr["checkpoint_sha256"],"Checkpoint binding")
                require(sha(rw/"checkpoint/global-model.json")==rr["global_model_sha256"],"Model binding")
                vp=w/f"evaluation/round-{r:03d}-validation.json"; v=read(vp)
                require(sha(vp)==rr["validation_metrics_sha256"] and not v["test_data_observed"],"Validation binding")
                m=v["validation"]; vk,vn=asr(m)
                trajectories.append(dict(seed=seed,arm=arm,round=r,macro_f1=m["macro_f1_all_model_classes"],asr=vk/vn,target_errors=vk,target_examples=vn))
                paths=list((rw/"in-round-decisions").glob("*.json"))
                bound={x["decision_sha256"] for x in cp["accepted_inputs"]}|set(cp["quarantined_decision_sha256"])
                require(len(paths)==15 and {sha(p) for p in paths}==bound,"Decision bindings")
                for p in paths:
                    d=read(p)["core"]
                    decisions.append(dict(seed=seed,arm=arm,round=r,client=d["client_id"],group="attacker" if arm=="adaptive" and r>=11 and d["client_id"] in attackers else "honest",status=d["final_status"]))
                if arm=="adaptive" and r<=10:
                    require((rw/"checkpoint/global-model.json").read_bytes()==(pair/f"clean/rounds/round-{r:03d}/checkpoint/global-model.json").read_bytes(),"Pre-attack equality")
                if arm=="adaptive" and r>=11:
                    sp=rw/"adaptive-search/summary.json"; s=read(sp); selection=read(rw/"adaptive-selection.json")["core"]
                    require(sha(sp)==selection["search_receipt_sha256"],"Search binding")
                    require(s["query_count"]==66 and not s["test_data_accessed"],"Query protocol")
                    for name,digest in s["source_bindings"].items(): require(sha(rw/name)==digest,name)
                    if s["selected_query"] is not None:
                        q=read(rw/f"adaptive-search/queries/{s['selected_query']:03d}/decision.json")
                        require(abs(q["validation_macro_f1"]-m["macro_f1_all_model_classes"])<1e-12 and q["targeted_asr"]==vk/vn,"Predicted/observed selection")
                    searches.append(dict(seed=seed,round=r,**{k:v for k,v in s.items() if k not in ("source_bindings","knowledge","semantics","selection_rule")}))
            local=[x for x in trajectories if x["seed"]==seed and x["arm"]==arm]
            require(max(local,key=lambda x:(x["macro_f1"],-x["round"]))["round"]==e["selected_round"],"Selection rule")
        row["delta_macro_f1"]=row["adaptive_test_macro_f1"]-row["clean_test_macro_f1"]
        row["delta_asr"]=row["adaptive_test_asr"]-row["clean_test_asr"]
        rows.append(row)
        print(f"Verified extraction seed {seed}",flush=True)
    aggregates={}
    for cohort,subset in [("all_five",rows),("four_new",rows[1:])]:
        aggregates[cohort]={k:stats([r[k] for r in subset]) for k in ("clean_test_macro_f1","adaptive_test_macro_f1","delta_macro_f1","clean_test_asr","adaptive_test_asr","delta_asr")}
    admissions=[]
    for seed in [r["seed"] for r in rows]:
        for arm,group in (("clean","honest"),("adaptive","honest"),("adaptive","attacker")):
            ds=[d for d in decisions if d["seed"]==seed and d["arm"]==arm and d["group"]==group and d["round"]>=11]
            admissions.append(dict(seed=seed,arm=arm,group=group,denominator=len(ds),counts=dict(Counter(d["status"] for d in ds))))
    summary=dict(seeds=rows,aggregates=aggregates,rounds=300,attack_search_queries=sum(s["query_count"] for s in searches),successful_validation_search_rounds=sum(bool(s["success_on_optimization_validation"]) for s in searches),admissions=admissions,new_inference_performed=False,scope="Descriptive paired analysis; one known exploratory reference plus four prespecified extensions. Seeds, not rounds/queries, are experimental units.")
    OUT.mkdir()
    write("summary.json",summary); write("trajectories.json",trajectories); write("searches.json",searches); write("admission-decisions.json",decisions)
    with (OUT/"per-seed.csv").open("w",newline="") as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    plt.rcParams.update({"font.size":10,"axes.spines.top":False,"axes.spines.right":False})
    fig,axs=plt.subplots(1,2,figsize=(11,4))
    for i,r in enumerate(rows):
        axs[0].plot([0,1],[r["clean_test_macro_f1"],r["adaptive_test_macro_f1"]],marker="o",label=str(r["seed"])+(" (reference)" if i==0 else ""))
    axs[0].set(xticks=[0,1],xticklabels=["Clean","Adaptive"],ylabel="Selected test macro-F1",title="Each line is one paired seed")
    axs[0].legend(fontsize=8)
    axs[1].bar([str(r["seed"]) for r in rows],[100*r["delta_macro_f1"] for r in rows],color=["#888888"]+["#2471a3"]*4)
    axs[1].axhline(0,color="black",linewidth=.8); axs[1].set(ylabel="Adaptive minus clean (percentage points)",title="Descriptive paired differences"); axs[1].tick_params(axis="x",rotation=30)
    figure(fig,"paired-test-macro-f1")
    fig,axs=plt.subplots(2,5,figsize=(17,6),sharex=True,sharey="row")
    for i,row in enumerate(rows):
        for arm,color in (("clean","#2471a3"),("adaptive","#c0392b")):
            values=[t for t in trajectories if t["seed"]==row["seed"] and t["arm"]==arm]
            for j,key in enumerate(("macro_f1","asr")):
                axs[j,i].plot([v["round"] for v in values],[v[key] for v in values],label=arm,color=color,linestyle="--" if arm=="adaptive" else "-")
                axs[j,i].axvspan(10.5,30,alpha=.05,color="orange")
            chosen=next(t for t in values if t["round"]==row[f"{arm}_selected_round"])
            axs[0,i].scatter(chosen["round"],chosen["macro_f1"],color=color,marker="*",s=75)
        axs[0,i].set_title(str(row["seed"])+(" reference" if i==0 else ""))
        axs[1,i].set_xlabel("Round"); axs[1,i].set_ylim(bottom=0,top=max(.01,max(t["asr"] for t in trajectories)*1.1))
    axs[0,0].set_ylabel("Validation macro-F1"); axs[1,0].set_ylabel("Targeted validation ASR"); axs[0,0].legend()
    figure(fig,"validation-trajectories")
    fig,ax=plt.subplots(figsize=(10,4))
    for row in rows:
        ss=[s for s in searches if s["seed"]==row["seed"]]
        ax.plot([s["round"] for s in ss],[100*s["selected_validation_drop"] if s["selected_validation_drop"] is not None else float("nan") for s in ss],label=str(row["seed"]))
    ax.axhline(0,color="black",linewidth=.7); ax.set(xlabel="Attacked round",ylabel="Macro-F1 drop (percentage points)",title="Immediate change versus untouched proposals on the SAME adaptive state")
    ax.legend(ncol=5,fontsize=8); figure(fig,"within-state-effects")
    fig,axs=plt.subplots(1,3,figsize=(14,4))
    for ax,(arm,group,denom) in zip(axs,[("clean","honest",300),("adaptive","honest",240),("adaptive","attacker",60)]):
        aa=[a for a in admissions if a["arm"]==arm and a["group"]==group]; bottom=[0]*5
        for status,color in [("accepted","#2471a3"),("accepted_downweighted","#f39c12"),("statistically_quarantined","#c0392b")]:
            values=[a["counts"].get(status,0) for a in aa]
            ax.bar(range(5),values,bottom=bottom,label=status,color=color); bottom=[b+v for b,v in zip(bottom,values)]
        require(bottom==[denom]*5,"Admission categories/denominators")
        ax.set(xticks=range(5),xticklabels=[str(r["seed"]) for r in rows],title=f"{arm} {group}: {denom}/seed",ylabel="Decisions, rounds 11–30"); ax.tick_params(axis="x",rotation=40)
    axs[2].legend(fontsize=8); figure(fig,"admission-counts")
    table="\n".join(f"| {r['seed']} | {r['clean_test_macro_f1']:.6f} | {r['adaptive_test_macro_f1']:.6f} | {100*r['delta_macro_f1']:+.4f} | {r['clean_target_errors']}/{r['clean_target_examples']} | {r['adaptive_target_errors']}/{r['adaptive_target_examples']} |" for r in rows)
    text=f"""# Adaptive paired multiseed — completed 2026-09-30

One exploratory reference (341593, v4) and four prespecified extensions (342593–345593).
Five pairs, 30 rounds per arm, 300 rounds total. The extension itself adds 240 rounds.
This report reads stored evaluations only; no new training, attack tuning or test inference.

## Selected-checkpoint outcomes

| Seed | Clean macro-F1 | Adaptive macro-F1 | Difference (pp) | Clean target errors | Adaptive target errors |
|---|---:|---:|---:|---:|---:|
{table}

All-five paired macro-F1 difference: mean {100*aggregates['all_five']['delta_macro_f1']['mean']:+.4f} pp,
sample SD {100*aggregates['all_five']['delta_macro_f1']['sample_sd']:.4f} pp.
Four-new-seed difference: mean {100*aggregates['four_new']['delta_macro_f1']['mean']:+.4f} pp,
sample SD {100*aggregates['four_new']['delta_macro_f1']['sample_sd']:.4f} pp.
Individual outcomes and mean/sample SD for both cohorts are in summary.json.
These are descriptive statistics, not a superiority/equivalence test.

## Interpretation

Targeted ASR counts true reconnaissance samples predicted benign divided by all
reconnaissance samples. The same held-out dataset is reused across seeds: do not
treat repeated test examples as independent observations or pool denominators as
new independent samples. Zero ASR does not imply perfect multiclass classification.
Maximum validation macro-F1 (earliest tie) selects each model separately.

Admission of malicious contributions and attack success are different outcomes.
There are 60 malicious client-rounds per seed, 240 honest adaptive client-rounds
and 300 clean client-rounds during rounds 11–30. See admission-counts and summary.json.
Within-state drops compare an attacked candidate against untouched proposals on
the adaptive state, not against the separate clean trajectory.
The optimizer has privileged validation and all proposals; this is a strong-knowledge
stress test, not a guaranteed upper bound over possible attacks.
The first seed was already observed before fixing the extension; this is not an
entirely fresh confirmatory study. Five seeds are a small sample. Do not claim
universal robustness, general attack failure or beneficial poisoning.

## Cost, failures and verification scope

{summary['attack_search_queries']} search queries across 100 attacked rounds, plus
independent campaign recomputation; {summary['successful_validation_search_rounds']}
rounds meet the locked validation success criterion. Query counts are not CPU time.
Exact wall-clock/GPU cost was not reconstructed by this report.
The first reference retained its documented v1–v3 failures and v4 recovery.
The extension had two pre-training invocation failures; recovery2 used the absolute
runner path and explicit numeric wrapper without altering the locked protocol.
See [execution history](../../docs/M6_ADAPTIVE_MULTIROUND.md) and local recovery receipts.
No failed attempts were converted into successful observations or discarded.

The extractor checks completion receipts, source locks, checkpoint/model/evaluation
and decision hashes, exact first-ten-round equality, selected-query metrics, query
budget and model selection. It does not rerun the expensive optimizer or replace
the independent campaign verifiers. Existing M8 packages do not cover this extension.

## Outputs

- paired-test-macro-f1: paired endpoints and differences.
- validation-trajectories: every seed and both arms; stars mark selected checkpoints.
- within-state-effects: immediate attack effects, with distinct counterfactual scope.
- admission-counts: honest/malicious interventions with explicit denominators.

Figures are PNG and vector PDF; data are CSV/JSON. manifest.json binds the files read
and generated. Run once with python scripts/report_m6_adaptive_multiseed_v1.py.
Existing output is protected from overwriting.
"""
    (OUT/"README.md").write_text(text)
    SOURCES[str(Path(__file__).relative_to(ROOT))]=sha(Path(__file__))
    write("manifest.json",dict(sources=SOURCES,outputs={p.name:sha(p) for p in sorted(OUT.iterdir())}))
    print(json.dumps(dict(aggregates=aggregates,seeds=rows),indent=2))
if __name__=="__main__": main()