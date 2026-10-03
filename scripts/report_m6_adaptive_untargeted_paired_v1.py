"""Report verified results from the M6 untargeted four-arm campaign."""
import argparse
import csv
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT=Path(__file__).resolve().parents[1]
ARMS=("gated_clean","gated_adaptive","tpm_clean","tpm_adaptive")

def read(p): return json.loads(p.read_text())
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def put(path,text):
    with path.open("x",encoding="utf-8",newline="") as f:f.write(text)
def write_json(path,value):
    put(path,json.dumps(value,indent=2,sort_keys=True,ensure_ascii=False)+"\n")
def write_csv(path,rows,fields):
    with path.open("x",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def f1(value): return value["macro_f1_all_model_classes"]
def test_asr(metrics):
    cm=metrics["confusion_matrix"];labels=cm["labels"];values=cm["values"]
    if "reconnaissance" not in labels or "benign" not in labels:return None
    i=labels.index("reconnaissance");j=labels.index("benign")
    denominator=sum(values[i])
    return None if denominator==0 else values[i][j]/denominator
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--campaign",type=Path,default=ROOT/"artifacts/m6-adaptive-untargeted-paired-s342593-v1")
    parser.add_argument("--output",type=Path,default=ROOT/"results/m6-adaptive-untargeted-paired-s342593-v1")
    args=parser.parse_args();campaign=args.campaign.resolve();out=args.output.resolve()
    complete=read(campaign/"complete.json")
    if complete.get("status")!="verified" or complete.get("rounds_per_arm")!=30:
        raise ValueError("Campaign lacks verified completion marker")
    if complete.get("arms")!=list(ARMS) or complete.get("test_data_accessed") is not True:
        raise ValueError("Campaign completion marker differs from report protocol")
    out.mkdir(parents=True,exist_ok=False)
    cells=[];rounds=[];admissions=[];per_arm={}
    for arm in ARMS:
        root=campaign/arm
        evaluation=read(root/"evaluation/selected-checkpoint-evaluation.json")
        test=evaluation["metrics"]["test"]
        validation=evaluation["metrics"]["validation"]
        info={"arm":arm,"policy":"gated_composite" if arm.startswith("gated") else "tpm_only",
              "treatment":"adaptive" if arm.endswith("adaptive") else "clean",
              "selected_round":evaluation["selected_round"],
              "selected_test_macro_f1":f1(test),
              "selected_test_accuracy":test["accuracy"],
              "selected_test_recon_to_benign_asr":test_asr(test),
              "selected_validation_macro_f1":f1(validation),
              "test_per_class":test["per_class"]}
        per_arm[arm]=info
        cells.append({k:v for k,v in info.items() if k!="test_per_class"})
        for number in range(1,31):
            r=root/"rounds"/f"round-{number:03d}"
            val=read(root/"evaluation"/f"round-{number:03d}-validation.json")["validation"]
            search_path=r/"adaptive-search/summary.json"
            search=read(search_path) if search_path.is_file() else {}
            rounds.append({"arm":arm,"policy":info["policy"],"treatment":info["treatment"],
                "round":number,"validation_macro_f1":f1(val),
                "attack_active":bool(search),"selected_query":search.get("selected_query"),
                "attack_validation_drop":search.get("selected_validation_drop"),
                "attack_search_success":search.get("success_on_optimization_validation")})
            decision_dir=r/"in-round-decisions"
            if decision_dir.is_dir():
                for p in sorted(decision_dir.glob("client*.json")):
                    core=read(p)["core"]
                    admissions.append({"arm":arm,"policy":info["policy"],"round":number,
                        "client_id":core["client_id"],
                        "status":core.get("final_status",core.get("status","unknown")),
                        "effective_weight":core.get("effective_weight_decimal","")})
            else:
                for p in sorted((r/"decisions").glob("client*.json")):
                    core=read(p)["core"]
                    admissions.append({"arm":arm,"policy":info["policy"],"round":number,
                        "client_id":core.get("client_id",""),
                        "status":core.get("status","unknown"),
                        "effective_weight":""})
    losses={}
    for policy,clean,adaptive in (
        ("gated_composite","gated_clean","gated_adaptive"),
        ("tpm_only","tpm_clean","tpm_adaptive")):
        loss=per_arm[clean]["selected_test_macro_f1"]-per_arm[adaptive]["selected_test_macro_f1"]
        losses[policy]=loss
    difference=losses["tpm_only"]-losses["gated_composite"]
    intervention_counts={}
    for row in admissions:
        key=(row["policy"],row["status"])
        intervention_counts[key]=intervention_counts.get(key,0)+1
    summary={"artifact_type":"m6_adaptive_untargeted_four_arm_report",
        "status":"reported_from_verified_campaign","experiment_id":"m6-adaptive-untargeted-paired-s342593-v1",
        "campaign_complete_sha256":sha(campaign/"complete.json"),
        "execution_lock_sha256":sha(campaign/"execution-lock.json"),
        "policy_paired_test_macro_f1_loss":losses,
        "difference_of_paired_losses_tpm_minus_gated":difference,
        "prespecified_practical_threshold":0.01,
        "practical_success_by_policy":{k:(v>=0.01) for k,v in losses.items()},
        "arm_metrics":per_arm,
        "admission_status_counts":{f"{k[0]}:{k[1]}":v for k,v in sorted(intervention_counts.items())},
        "seed_count":1,"inferential_scope":"descriptive single-seed exploratory study"}
    write_csv(out/"cells.csv",cells,list(cells[0]))
    write_csv(out/"rounds.csv",rounds,list(rounds[0]))
    write_csv(out/"admissions.csv",admissions,["arm","policy","round","client_id","status","effective_weight"])
    write_json(out/"summary.json",summary)

    colors={"gated_clean":"#2a6fbb","gated_adaptive":"#e07a27",
            "tpm_clean":"#479b73","tpm_adaptive":"#ba4b51"}
    fig,ax=plt.subplots(figsize=(10,5.8))
    for arm in ARMS:
        xs=[r["round"] for r in rounds if r["arm"]==arm]
        ys=[r["validation_macro_f1"] for r in rounds if r["arm"]==arm]
        ax.plot(xs,ys,label=arm.replace("_"," "),color=colors[arm],
                linestyle="--" if arm.endswith("adaptive") else "-",linewidth=1.8)
    ax.axvline(10.5,color="#555",linestyle=":",linewidth=1)
    ax.text(10.7,0.02,"adaptive treatment starts",transform=ax.get_xaxis_transform(),
            fontsize=8,color="#555")
    ax.set(xlabel="Round",ylabel="Validation macro-F1 (all model classes)",
           title="Validation trajectories by admission policy and attack")
    ax.set_xlim(1,30);ax.grid(alpha=.22);ax.legend(ncol=2,frameon=False)
    fig.tight_layout();fig.savefig(out/"validation-trajectories.png",dpi=180);plt.close(fig)

    fig,ax=plt.subplots(figsize=(8,5.4))
    labels=["Gated-composite","TPM-only"]
    x=[0,1];width=.34
    clean=[per_arm["gated_clean"]["selected_test_macro_f1"],per_arm["tpm_clean"]["selected_test_macro_f1"]]
    attacked=[per_arm["gated_adaptive"]["selected_test_macro_f1"],per_arm["tpm_adaptive"]["selected_test_macro_f1"]]
    ax.bar([v-width/2 for v in x],clean,width,label="Clean",color="#4c78a8")
    ax.bar([v+width/2 for v in x],attacked,width,label="Adaptive",color="#e45756")
    ax.set_xticks(x,labels);ax.set_ylim(0,1);ax.set_ylabel("Selected-checkpoint test macro-F1")
    ax.set_title("Held-out test performance after all trajectories verified")
    ax.grid(axis="y",alpha=.2);ax.legend(frameon=False)
    fig.tight_layout();fig.savefig(out/"selected-test-macro-f1.png",dpi=180);plt.close(fig)

    fig,ax=plt.subplots(figsize=(7,4.8))
    vals=[losses["gated_composite"],losses["tpm_only"]]
    bars=ax.bar(["Gated-composite","TPM-only"],vals,color=["#4c78a8","#e45756"])
    ax.axhline(.01,color="#555",linestyle="--",label="Prespecified 0.01 threshold")
    ax.bar_label(bars,fmt="%.4f",padding=3)
    ax.set_ylabel("Clean minus adaptive test macro-F1")
    ax.set_title("Paired selected-checkpoint test loss")
    ax.grid(axis="y",alpha=.2);ax.legend(frameon=False)
    fig.tight_layout();fig.savefig(out/"paired-test-loss.png",dpi=180);plt.close(fig)

    for name,path in []: pass
    report=f"""# Untargeted adaptive live M6 results

The report reads only the completed, independently verified four-arm campaign.
The test set was evaluated by the fixed M5 finalizer after every arm completed its
30 rounds. The validation-driven attack never read test.

| Policy | Clean selected test macro-F1 | Adaptive selected test macro-F1 | Paired loss (clean - adaptive) |
|---|---:|---:|---:|
| Gated-composite | {per_arm['gated_clean']['selected_test_macro_f1']:.4f} | {per_arm['gated_adaptive']['selected_test_macro_f1']:.4f} | {losses['gated_composite']:+.4f} |
| TPM-only | {per_arm['tpm_clean']['selected_test_macro_f1']:.4f} | {per_arm['tpm_adaptive']['selected_test_macro_f1']:.4f} | {losses['tpm_only']:+.4f} |

The prespecified difference in paired losses (TPM-only minus gated-composite) is
{difference:+.4f}. A positive value means the observed loss was larger under
TPM-only. The practical threshold was 0.01 absolute macro-F1. This is a single
seed, so these numbers are descriptive and do not establish statistical significance
or general robustness.

The adversary optimized all-class validation cross-entropy and selected proposals
by validation macro-F1. Results can therefore reflect optimization-set adaptation;
they must be interpreted against the untouched test endpoint and the limited
66-query/round budget. The full evidence preserves selected rounds, per-round
validation curves, candidate decisions and contribution admission outcomes.

![Validation trajectories](validation-trajectories.png)

![Selected test macro-F1](selected-test-macro-f1.png)

![Paired test loss](paired-test-loss.png)

See `summary.json`, `cells.csv`, `rounds.csv` and `admissions.csv`. Campaign
completion SHA-256: `{summary['campaign_complete_sha256']}`.
"""
    put(out/"README.md",report)
    manifest={"artifact_type":"m6_adaptive_untargeted_report_manifest",
        "summary_sha256":sha(out/"summary.json"),
        "files":{p.name:sha(p) for p in sorted(out.iterdir()) if p.is_file()}}
    write_json(out/"manifest.json",manifest)
    print(json.dumps({"status":"reported_from_verified_campaign","output":str(out),
        "policy_paired_test_macro_f1_loss":losses,
        "difference_of_paired_losses_tpm_minus_gated":difference,
        "figure_count":3,"manifest_sha256":sha(out/"manifest.json")},indent=2))

if __name__=="__main__":main()
