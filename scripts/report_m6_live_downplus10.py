"""Source-bound descriptive report; run after all M5 campaign verifiers pass."""
from pathlib import Path
from collections import Counter
import csv
import hashlib
import json
import numpy as np
from scipy.stats import t
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/m6-live-downplus10-v1"
SEEDS = [341593, 342593, 343593, 344593, 345593]
POLICIES = ["original", "downplus10"]
CONDITIONS = ["clean", "disagreement"]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path):
    return json.loads(path.read_text())

def stats(values):
    a = np.asarray(values, dtype=float)
    mean = float(a.mean())
    sd = float(a.std(ddof=1))
    margin = float(t.ppf(0.975, len(a)-1) * sd / np.sqrt(len(a)))
    return dict(n=len(a), mean=mean, sample_sd=sd, ci95=[mean-margin, mean+margin])

def main():
    if OUT.exists():
        raise FileExistsError(f"Preserve existing report: {OUT}")
    logs = [p for pattern in ("m6-policy-pilot-*.log", "m6-policy-multiseed-*.log", "m6-policy-resume-*.log", "m6-policy-last-*.log", "m6-downplus10-*.log") for p in ROOT.glob(pattern)]
    markers = {line.removeprefix("VERIFIED: ") for p in logs for line in p.read_text().splitlines() if line.startswith("VERIFIED: ")}
    recovery = (ROOT / "m6-downplus10-recovery-verification-20260925-b.log").read_text()
    final, _ = json.JSONDecoder().raw_decode(recovery[recovery.rfind("\n{")+1:])
    assert final["status"] == "verified" and final["error_count"] == 0 and final["round_count"] == 30 and final["workspace"] == "/coordinator"
    markers.add("m6-downplus10-disagreement-s341593-v1")
    runs, rounds, sources = [], [], {}
    for seed in SEEDS:
        shared_partition = None
        for policy in POLICIES:
            for condition in CONDITIONS:
                phase = "pilot" if seed == 341593 else "multiseed"
                name = f"m6-policy-{phase}-gated_composite-{condition}-s{seed}-v1" if policy == "original" else f"m6-downplus10-{condition}-s{seed}-v1"
                assert name in markers, f"Missing successful campaign verification marker: {name}"
                w = ROOT / "artifacts" / name
                mp = w / "campaign-manifest.json"
                m = read(mp)["core"]
                assert m["round_count"] == 30
                shared_partition = shared_partition or m["partition_manifest_sha256"]
                assert shared_partition == m["partition_manifest_sha256"]
                ep = w / "evaluation/selected-checkpoint-evaluation.json"
                assert sha(ep) == m["final_evaluation_sha256"]
                e = read(ep)
                safe, unsafe = Counter(), Counter()
                for rr in m["rounds"]:
                    n = rr["round_number"]
                    rw = w / f"rounds/round-{n:03d}"
                    cp = rw / "checkpoint/manifest.json"
                    assert sha(cp) == rr["checkpoint_sha256"]
                    c = read(cp)["core"]
                    assert c["aggregation_strategy"] == "FedAvg-gated-composite"
                    ac = rw / "public/in-round-admission-contract.json"
                    assert sha(ac) == c["admission_contract_sha256"]
                    contract = read(ac)["core"]
                    cfg = "in-round-admission.yaml" if policy == "original" else "in-round-admission-downplus10-v1.yaml"
                    assert contract["policy_config_sha256"] == sha(ROOT / "configs" / cfg)
                    federation = __import__("yaml").safe_load((rw / "public/federation.yaml").read_text())
                    assert federation["training"]["seed"] == federation["partitioning"]["seed"] == seed
                    assert federation["training"]["device"] == "cpu"
                    decisions = list((rw / "in-round-decisions").glob("*.json"))
                    assert len(decisions) == 15
                    bound = {v["decision_sha256"] for v in c["accepted_inputs"]} | set(c["quarantined_decision_sha256"])
                    assert {sha(d) for d in decisions} == bound
                    for d in decisions:
                        v = read(d)["core"]
                        target = unsafe if condition == "disagreement" and v["client_id"] in ("client02", "client03", "client04") else safe
                        target[v["final_status"]] += 1
                    vp = w / f"evaluation/round-{n:03d}-validation.json"
                    assert sha(vp) == rr["validation_metrics_sha256"]
                    v = read(vp)
                    assert not v["test_data_observed"]
                    rounds.append(dict(seed=seed, policy=policy, condition=condition, round=n, validation_f1=v["validation"]["macro_f1_all_model_classes"]))
                assert sum(safe.values()) + sum(unsafe.values()) == 450
                row = dict(seed=seed, policy=policy, condition=condition, selected_round=m["selected_round"], test_f1=e["metrics"]["test"]["macro_f1_all_model_classes"], validation_f1=e["metrics"]["validation"]["macro_f1_all_model_classes"], safe_total=sum(safe.values()), safe_quarantined=sum(v for k,v in safe.items() if k.endswith("quarantined")), safe_downweighted=safe["accepted_downweighted"], unsafe_total=sum(unsafe.values()), unsafe_quarantined=sum(v for k,v in unsafe.items() if k.endswith("quarantined")), unsafe_retained=unsafe["accepted"]+unsafe["accepted_downweighted"])
                runs.append(row)
                sources[name] = dict(manifest_sha256=sha(mp), evaluation_sha256=sha(ep), campaign_id=m["campaign_id"])
    summary = {condition: {policy: stats([r["test_f1"] for r in runs if r["condition"] == condition and r["policy"] == policy]) for policy in POLICIES} for condition in CONDITIONS}
    paired = {}
    for condition in CONDITIONS:
        diffs = [next(r["test_f1"] for r in runs if r["seed"] == seed and r["policy"] == POLICIES[1] and r["condition"] == condition) - next(r["test_f1"] for r in runs if r["seed"] == seed and r["policy"] == POLICIES[0] and r["condition"] == condition) for seed in SEEDS]
        paired[condition] = dict(differences=diffs, **stats(diffs))
    OUT.mkdir(parents=True)
    for name, data in (("runs.csv", runs), ("rounds.csv", rounds)):
        with (OUT/name).open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(data[0])); writer.writeheader(); writer.writerows(data)
    (OUT/"summary.json").write_text(json.dumps(dict(summary=summary, paired_variant_minus_original=paired, sources=sources, verification_scope="Prior M5 verifier success markers plus source digest, decision binding, seed and partition checks; not a replacement cryptographic verifier"), indent=2)+"\n")
    plt.rcParams.update({"font.size":10, "axes.spines.top":False, "axes.spines.right":False})
    def save(fig, name):
        fig.savefig(OUT/f"{name}.png", dpi=170, bbox_inches="tight")
        fig.savefig(OUT/f"{name}.pdf", bbox_inches="tight")
        plt.close(fig)
    fig, axes = plt.subplots(1,2, figsize=(11,4), layout="constrained")
    for ax, condition in zip(axes, CONDITIONS):
        for policy in POLICIES:
            values = [next(r["test_f1"] for r in runs if r["seed"]==seed and r["policy"]==policy and r["condition"]==condition) for seed in SEEDS]
            ax.plot(range(5), values, "o-", label=policy)
        ax.set(title=condition, ylabel="Selected-checkpoint test macro-F1", xticks=range(5), xticklabels=[str(s) for s in SEEDS]); ax.tick_params(axis="x", rotation=30); ax.legend()
    save(fig,"test-f1-by-seed")
    fig, ax=plt.subplots(figsize=(8,4), layout="constrained")
    for i, condition in enumerate(CONDITIONS):
        item=paired[condition]; ax.scatter(item["differences"], np.full(5,i), alpha=.7, label="Seed differences" if i==0 else None)
        ax.errorbar(item["mean"], i+.15, xerr=[[item["mean"]-item["ci95"][0]], [item["ci95"][1]-item["mean"]]], fmt="D", color="black", capsize=5, label="Mean and 95% t interval" if i==0 else None)
    ax.axvline(0,color="gray",linestyle="--"); ax.set(yticks=[0,1],yticklabels=CONDITIONS,xlabel="Paired test macro-F1: variant minus original"); ax.legend(); save(fig,"paired-differences")
    fig, axes=plt.subplots(1,2,figsize=(11,4),layout="constrained")
    for ax, condition in zip(axes,CONDITIONS):
        subset=[r for r in runs if r["condition"]==condition]
        q=[100*sum(r["safe_quarantined"] for r in subset if r["policy"]==pol)/sum(r["safe_total"] for r in subset if r["policy"]==pol) for pol in POLICIES]
        d=[100*sum(r["safe_downweighted"] for r in subset if r["policy"]==pol)/sum(r["safe_total"] for r in subset if r["policy"]==pol) for pol in POLICIES]
        ax.bar(POLICIES,q,label="Quarantined");ax.bar(POLICIES,d,bottom=q,label="Downweighted");ax.set(title=condition,ylabel="Declared-safe contributions (%)");ax.legend()
    save(fig,"benign-interventions")
    fig, axes=plt.subplots(2,2,figsize=(12,8),layout="constrained")
    for i,condition in enumerate(CONDITIONS):
        for j,policy in enumerate(POLICIES):
            ax=axes[i,j]
            for seed in SEEDS:
                rs=[r for r in rounds if r["condition"]==condition and r["policy"]==policy and r["seed"]==seed]
                line=ax.plot([r["round"] for r in rs],[r["validation_f1"] for r in rs],label=str(seed),alpha=.8)[0]
                chosen=next(r for r in runs if r["condition"]==condition and r["policy"]==policy and r["seed"]==seed)
                ax.scatter(chosen["selected_round"],chosen["validation_f1"],color=line.get_color(),marker="*",s=70)
            ax.set(title=f"{condition} / {policy}",xlabel="Round (* = selected)",ylabel="Validation macro-F1");ax.legend(fontsize=8)
    save(fig,"validation-trajectories")
    print(json.dumps(dict(summary=summary,paired=paired,interventions=runs),indent=2))

if __name__ == "__main__":
    main()
