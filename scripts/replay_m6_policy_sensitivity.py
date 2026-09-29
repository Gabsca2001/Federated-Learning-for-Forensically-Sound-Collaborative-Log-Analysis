"""Fixed-signal sensitivity using the production policy function; never opens test data."""
from pathlib import Path
from collections import Counter
from decimal import Decimal
import csv
import json
import hashlib
import argparse
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from fl_forensics.composite_admission import decide_admission_policies
from fl_forensics.composite_admission_models import TrustSignal, StatisticalSignal

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/m6-policy-sensitivity-replay-v1.json"
OUT = ROOT / "results/m6-policy-sensitivity-replay-v1"

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def read(p):
    return json.loads(p.read_text())

def run():
    config = read(CONFIG)
    rows, source_hashes = [], {}
    for seed in config["seeds"]:
        for source_policy in config["source_policies"]:
            for condition in config["conditions"]:
                phase = "pilot" if seed == 341593 else "multiseed"
                w = ROOT / "artifacts" / f"m6-policy-{phase}-{source_policy}-{condition}-s{seed}-v1"
                mp = w / "campaign-manifest.json"
                source_hashes[str(mp.relative_to(ROOT))] = sha(mp)
                manifest = read(mp)["core"]
                assert manifest["round_count"] == 30
                observations = []
                for rr in manifest["rounds"]:
                    rw = w / f"rounds/round-{rr['round_number']:03d}"
                    cp = rw / "checkpoint/manifest.json"
                    assert sha(cp) == rr["checkpoint_sha256"]
                    checkpoint = read(cp)["core"]
                    contract_path = rw / "public/in-round-admission-contract.json"
                    assert sha(contract_path) == checkpoint["admission_contract_sha256"]
                    core = read(contract_path)["core"]
                    assert core["primary_policy"] == source_policy
                    thresholds = core["thresholds"]
                    if observations:
                        assert thresholds == observations[0][1]
                    paths = list((rw / "in-round-decisions").glob("*.json"))
                    assert len(paths) == 15
                    bound = {v["decision_sha256"] for v in checkpoint["accepted_inputs"]} | set(checkpoint["quarantined_decision_sha256"])
                    assert {sha(d) for d in paths} == bound
                    for path in paths:
                        d = read(path)["core"]
                        # Replay is confined to intact, statistically scored contributions.
                        assert d["statistics"] is not None and d["final_status"] != "integrity_quarantined"
                        trust = TrustSignal.model_validate(d["trust"])
                        statistics = StatisticalSignal.model_validate(d["statistics"])
                        decisions = decide_admission_policies(trust=trust, statistics=statistics,
                            statistical_threshold=thresholds["statistical_threshold"],
                            composite_threshold=thresholds["composite_threshold"],
                            composite_downweight_threshold=thresholds["composite_downweight_threshold"],
                            trust_weight=thresholds["trust_weight"])
                        original = next(v for v in decisions if v.policy == source_policy)
                        assert original.model_dump(mode="json") == d["primary_decision"]
                        assert original.status == d["final_status"]
                        expected = Decimal(d["num_examples"]) * (Decimal(str(core["accepted_downweight_factor"])) if original.status == "accepted_downweighted" else Decimal(1) if original.status == "accepted" else Decimal(0))
                        assert expected == Decimal(d["effective_weight_decimal"])
                        observations.append((d, thresholds))
                assert len(observations) == 450
                for variant in config["variants"]:
                    counts = Counter(); weights = Counter()
                    for d, thresholds in observations:
                        outcome = next(v for v in decide_admission_policies(
                            trust=TrustSignal.model_validate(d["trust"]), statistics=StatisticalSignal.model_validate(d["statistics"]),
                            statistical_threshold=thresholds["statistical_threshold"],
                            composite_threshold=thresholds["composite_threshold"]*variant["quarantine_multiplier"],
                            composite_downweight_threshold=thresholds["composite_downweight_threshold"]*variant["down_multiplier"],
                            trust_weight=thresholds["trust_weight"]) if v.policy == "gated_composite")
                        if not d["trust"]["admissible"]:
                            assert outcome.status == "trust_quarantined"
                        label = "unsafe" if condition == "disagreement" and d["client_id"] in ("client02","client03","client04") else "safe"
                        counts[label+"_total"] += 1
                        counts[label+"_"+outcome.status] += 1
                        factor = 1 if outcome.status == "accepted" else variant["weight"] if outcome.status == "accepted_downweighted" else 0
                        weights[label+"_nominal_examples"] += d["num_examples"]
                        weights[label+"_effective_examples"] += d["num_examples"]*factor
                    row = dict(seed=seed, source_policy=source_policy, condition=condition, variant=variant["id"])
                    for label in ("safe","unsafe"):
                        row[label+"_total"] = counts[label+"_total"]
                        row[label+"_quarantined"] = counts[label+"_trust_quarantined"]+counts[label+"_statistically_quarantined"]
                        row[label+"_downweighted"] = counts[label+"_accepted_downweighted"]
                        row[label+"_accepted"] = counts[label+"_accepted"]
                        row[label+"_nominal_examples"] = weights[label+"_nominal_examples"]
                        row[label+"_effective_examples"] = weights[label+"_effective_examples"]
                    rows.append(row)
    return rows, source_hashes

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--verify",action="store_true");args=parser.parse_args()
    rows,sources=run()
    payload=dict(config_sha256=sha(CONFIG), generator_sha256=sha(Path(__file__)), source_manifests=sources, original_decisions_recomputed=9000, variant_decisions=63000, test_data_accessed=False, rows=rows)
    if args.verify:
        assert read(OUT/"summary.json")==payload
        print("Verified replay: 9000 baseline decisions and 63000 variant decisions recomputed; no test files opened.")
        return
    if OUT.exists():
        raise FileExistsError(OUT)
    OUT.mkdir(parents=True)
    (OUT/"summary.json").write_text(json.dumps(payload,indent=2)+"\n")
    with (OUT/"per-seed.csv").open("w",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    aggregates=[]
    for policy in ("gated_composite","sequential"):
        for condition in ("clean","disagreement"):
            for variant in read(CONFIG)["variants"]:
                chosen=[r for r in rows if r["source_policy"]==policy and r["condition"]==condition and r["variant"]==variant["id"]]
                item=dict(source_policy=policy,condition=condition,variant=variant["id"])
                for k in rows[0]:
                    if k not in ("seed","source_policy","condition","variant"):
                        item[k]=sum(r[k] for r in chosen)
                aggregates.append(item)
    with (OUT/"aggregate.csv").open("w",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=list(aggregates[0]));writer.writeheader();writer.writerows(aggregates)
    for metric,title in (("interventions","Safe interventions (%)"),("weight","Safe nominal sample weight retained (%)")):
        fig,axes=plt.subplots(2,2,figsize=(13,9),layout="constrained")
        for i,policy in enumerate(("gated_composite","sequential")):
            for j,condition in enumerate(("clean","disagreement")):
                ax=axes[i,j];rr=[r for r in aggregates if r["source_policy"]==policy and r["condition"]==condition]
                x=list(range(len(rr)))
                if metric=="interventions":
                    q=[100*r["safe_quarantined"]/r["safe_total"] for r in rr];d=[100*r["safe_downweighted"]/r["safe_total"] for r in rr]
                    ax.bar(x,q,label="Quarantined");ax.bar(x,d,bottom=q,label="Downweighted");ax.legend()
                else:
                    ax.bar(x,[100*r["safe_effective_examples"]/r["safe_nominal_examples"] for r in rr]);ax.set_ylim(0,100)
                ax.set(title=f"Recorded {policy} / {condition}",ylabel=title,xticks=x,xticklabels=[r["variant"] for r in rr]);ax.tick_params(axis="x",rotation=35)
        fig.savefig(OUT/f"{metric}.png",dpi=160,bbox_inches="tight");fig.savefig(OUT/f"{metric}.pdf",bbox_inches="tight");plt.close(fig)
    print(json.dumps(aggregates,indent=2))

if __name__=="__main__":
    main()
