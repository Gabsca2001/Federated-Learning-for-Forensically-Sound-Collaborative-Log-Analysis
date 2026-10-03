"""Create a verified four-seed report for the untargeted adaptive M6 extension."""
import argparse
import csv
import hashlib
import json
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
SEEDS = (342593, 343593, 344593, 345593)
ARMS = ("gated_clean", "gated_adaptive", "tpm_clean", "tpm_adaptive")
ATTACKERS = {"client02", "client05", "client14"}
POLICIES = ("gated_composite", "tpm_only")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def write_csv(path, rows, fields):
    with path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_asr(metrics):
    matrix = metrics.get("confusion_matrix", {})
    labels = matrix.get("labels", [])
    values = matrix.get("values", [])
    if "reconnaissance" not in labels or "benign" not in labels:
        return None
    row = values[labels.index("reconnaissance")]
    denominator = sum(row)
    return None if denominator == 0 else row[labels.index("benign")] / denominator


def campaign_path(seed):
    if seed == 342593:
        return ROOT / "artifacts/m6-adaptive-untargeted-paired-s342593-v1-continuation-v3"
    return ROOT / f"artifacts/m6-adaptive-untargeted-paired-s{seed}-v1"


def collect():
    per_arm = []
    paired = []
    rounds = []
    admissions = []
    searches = []
    source_receipts = {}
    for seed in SEEDS:
        campaign = campaign_path(seed)
        complete_path = campaign / "complete.json"
        complete = read(complete_path)
        if (complete.get("status") != "verified"
                or complete.get("rounds_per_arm") != 30
                or complete.get("arms") != list(ARMS)
                or complete.get("test_data_accessed") is not True):
            raise ValueError(f"Seed {seed} lacks a verified four-arm completion")
        lock_path = campaign / "execution-lock.json"
        source_receipts[str(seed)] = {
            "campaign_complete_sha256": sha(complete_path),
            "execution_lock_sha256": sha(lock_path),
        }
        seed_metrics = {}
        for arm in ARMS:
            base = campaign / arm
            evaluation_path = base / "evaluation/selected-checkpoint-evaluation.json"
            evaluation = read(evaluation_path)
            test = evaluation["metrics"]["test"]
            validation = evaluation["metrics"]["validation"]
            policy = "gated_composite" if arm.startswith("gated") else "tpm_only"
            adaptive = arm.endswith("adaptive")
            info = {
                "seed": seed,
                "arm": arm,
                "policy": policy,
                "treatment": "adaptive" if adaptive else "clean",
                "selected_round": evaluation["selected_round"],
                "selected_validation_macro_f1": validation["macro_f1_all_model_classes"],
                "selected_test_macro_f1": test["macro_f1_all_model_classes"],
                "selected_test_accuracy": test["accuracy"],
                "selected_test_recon_to_benign_asr": test_asr(test),
                "test_per_class": test["per_class"],
            }
            per_arm.append({k: v for k, v in info.items() if k != "test_per_class"})
            seed_metrics[arm] = info

            success_count = 0
            for number in range(1, 31):
                round_root = base / "rounds" / f"round-{number:03d}"
                validation_record = read(base / "evaluation" / f"round-{number:03d}-validation.json")
                search_path = round_root / "adaptive-search/summary.json"
                search = read(search_path) if search_path.is_file() else {}
                success = search.get("success_on_optimization_validation")
                if success is True:
                    success_count += 1
                rounds.append({
                    "seed": seed, "arm": arm, "policy": policy,
                    "treatment": "adaptive" if adaptive else "clean",
                    "round": number,
                    "validation_macro_f1": validation_record["validation"]["macro_f1_all_model_classes"],
                    "attack_active": bool(search),
                    "selected_query": search.get("selected_query"),
                    "attack_validation_drop": search.get("selected_validation_drop"),
                    "attack_search_success": success,
                })
                decision_root = round_root / "in-round-decisions"
                is_gated = policy == "gated_composite"
                if is_gated:
                    paths = sorted(decision_root.glob("client*.json"))
                else:
                    paths = sorted((round_root / "decisions").glob("client*.json"))
                if len(paths) != 15:
                    raise ValueError(f"Seed {seed} {arm} round {number}: expected 15 decisions, got {len(paths)}")
                for decision_path in paths:
                    core = read(decision_path)["core"]
                    client_id = core.get("client_id", "")
                    attacker = adaptive and number >= 11 and client_id in ATTACKERS
                    status = core.get("final_status", core.get("status", "unknown"))
                    admissions.append({
                        "seed": seed, "arm": arm, "policy": policy,
                        "round": number, "client_id": client_id,
                        "group": "attacker" if attacker else "benign",
                        "status": status,
                    })
            if adaptive:
                searches.append({
                    "seed": seed, "policy": policy,
                    "successful_rounds": success_count,
                    "attacked_rounds": 20,
                    "success_rate": success_count / 20,
                })

        for policy, clean_arm, attacked_arm in (
            ("gated_composite", "gated_clean", "gated_adaptive"),
            ("tpm_only", "tpm_clean", "tpm_adaptive"),
        ):
            clean = seed_metrics[clean_arm]
            attacked = seed_metrics[attacked_arm]
            paired.append({
                "seed": seed, "policy": policy,
                "clean_selected_round": clean["selected_round"],
                "adaptive_selected_round": attacked["selected_round"],
                "clean_test_macro_f1": clean["selected_test_macro_f1"],
                "adaptive_test_macro_f1": attacked["selected_test_macro_f1"],
                "paired_loss_clean_minus_adaptive":
                    clean["selected_test_macro_f1"] - attacked["selected_test_macro_f1"],
            })

    outcomes = {}
    for policy in POLICIES:
        values = [r["paired_loss_clean_minus_adaptive"] for r in paired if r["policy"] == policy]
        outcomes[policy] = {
            "individual_seed_losses": {
                str(r["seed"]): r["paired_loss_clean_minus_adaptive"]
                for r in paired if r["policy"] == policy
            },
            "mean_loss": statistics.mean(values),
            "sample_sd_loss": statistics.stdev(values),
        }
    difference_rows = []
    for seed in SEEDS:
        losses = {r["policy"]: r["paired_loss_clean_minus_adaptive"]
                  for r in paired if r["seed"] == seed}
        difference_rows.append({
            "seed": seed,
            "tpm_minus_gated_paired_loss":
                losses["tpm_only"] - losses["gated_composite"],
        })
    difference_values = [row["tpm_minus_gated_paired_loss"] for row in difference_rows]
    outcomes["tpm_minus_gated_paired_loss"] = {
        "individual_seed_differences": {
            str(r["seed"]): r["tpm_minus_gated_paired_loss"] for r in difference_rows
        },
        "mean_difference": statistics.mean(difference_values),
        "sample_sd_difference": statistics.stdev(difference_values),
    }

    status_counts = {}
    for row in admissions:
        key = (row["seed"], row["policy"], row["group"], row["status"])
        status_counts[key] = status_counts.get(key, 0) + 1
    denominators = {}
    for row in admissions:
        key = (row["seed"], row["policy"], row["group"])
        denominators[key] = denominators.get(key, 0) + 1
    admission_summary = []
    for (seed, policy, group, status), count in sorted(status_counts.items()):
        denom = denominators[(seed, policy, group)]
        admission_summary.append({
            "seed": seed, "policy": policy, "group": group,
            "status": status, "count": count, "denominator": denom,
            "rate": count / denom,
        })

    summary = {
        "artifact_type": "m6_adaptive_untargeted_multiseed_report",
        "status": "reported_from_verified_campaigns",
        "seeds": list(SEEDS),
        "seed_count": len(SEEDS),
        "per_seed_outcomes": paired,
        "seed_level_descriptive_statistics": outcomes,
        "validation_search_success": searches,
        "admission_status_counts": admission_summary,
        "source_receipts": source_receipts,
        "inferential_scope":
            "Outcome-aware exploratory seed replication on one dataset; descriptive only, not confirmatory or independent-dataset evidence.",
        "test_inference_rerun": False,
    }
    return per_arm, paired, rounds, admission_summary, searches, summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path,
                        default=ROOT / "results/m6-adaptive-untargeted-multiseed-v1")
    args = parser.parse_args()
    out = args.output.resolve()
    per_arm, paired, rounds, admissions, searches, summary = collect()
    out.mkdir(parents=True, exist_ok=False)

    write_csv(out / "per-arm.csv", per_arm, list(per_arm[0]))
    write_csv(out / "paired-losses.csv", paired, list(paired[0]))
    write_csv(out / "rounds.csv", rounds, list(rounds[0]))
    write_csv(out / "admission-summary.csv", admissions, list(admissions[0]))
    write_csv(out / "search-success.csv", searches, list(searches[0]))
    write_json(out / "summary.json", summary)

    fig, ax = plt.subplots(figsize=(9, 5.6))
    x = list(range(len(SEEDS)))
    width = 0.34
    for offset, policy, label, color in (
        (-width / 2, "gated_composite", "Gated-composite", "#4c78a8"),
        (width / 2, "tpm_only", "TPM-only", "#e45756"),
    ):
        values = [r["paired_loss_clean_minus_adaptive"] for r in paired if r["policy"] == policy]
        ax.bar([i + offset for i in x], values, width, label=label, color=color)
        ax.scatter([i + offset for i in x], values, color="#222222", s=18, zorder=3)
    ax.axhline(0.01, color="#555555", linestyle="--", linewidth=1, label="0.01 practical threshold")
    ax.axhline(0, color="#999999", linewidth=.8)
    ax.set_xticks(x, [str(seed) for seed in SEEDS])
    ax.set_xlabel("Training/partition seed")
    ax.set_ylabel("Clean minus adaptive selected test macro-F1")
    ax.set_title("Per-seed paired test loss (descriptive)")
    ax.grid(axis="y", alpha=.2)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(out / "paired-loss-by-seed.png", dpi=180)
    plt.close(fig)

    groups = (("gated_composite", "attacker"), ("gated_composite", "benign"),
              ("tpm_only", "attacker"), ("tpm_only", "benign"))
    statuses = sorted({row["status"] for row in admissions})
    fig, ax = plt.subplots(figsize=(9, 5.6))
    labels = ["Gated / attackers", "Gated / benign", "TPM-only / attackers", "TPM-only / benign"]
    for i, (policy, group) in enumerate(groups):
        rows = [row for row in admissions if row["policy"] == policy and row["group"] == group]
        denom = sum(row["count"] for row in rows)
        bottom = 0.0
        for status in statuses:
            count = sum(row["count"] for row in rows if row["status"] == status)
            rate = count / denom if denom else 0.0
            ax.bar(i, rate, bottom=bottom, color={
                "accepted": "#4c78a8",
                "accepted_downweighted": "#f2cf5b",
                "statistically_quarantined": "#e45756",
            }.get(status, "#888888"), label=status if i == 0 else None)
            bottom += rate
    ax.set_xticks(range(len(groups)), labels)
    ax.set_ylim(0, 1)
    ax.set_ylabel("Share of contribution decisions")
    ax.set_title("Admission outcomes by attack-period status (pooled counts)")
    ax.grid(axis="y", alpha=.2)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(out / "admission-outcomes.png", dpi=180)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8.5, 5.2))
    for policy, label, color in (
        ("gated_composite", "Gated-composite", "#4c78a8"),
        ("tpm_only", "TPM-only", "#e45756"),
    ):
        rows = [r for r in searches if r["policy"] == policy]
        ax.plot([r["seed"] for r in rows], [r["success_rate"] for r in rows],
                marker="o", label=label, color=color)
    ax.set_ylim(-.03, 1.03)
    ax.set_xlabel("Training/partition seed")
    ax.set_ylabel("Validation search success rate (20 attacked rounds)")
    ax.set_title("Adaptive search success by seed")
    ax.grid(alpha=.22)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(out / "search-success-by-seed.png", dpi=180)
    plt.close(fig)

    means = summary["seed_level_descriptive_statistics"]
    readme = f"""# Untargeted adaptive M6 seed extension

This report combines four verified four-arm campaigns: the seed-342593
continuation and the locked seed replications 343593-345593. It reads preserved
M5 final evaluation and decision artifacts; it does not rerun test inference.
Search and checkpoint selection used validation only.

## Paired selected-checkpoint test loss

Loss is clean minus adaptive test macro-F1; positive values mean the adaptive
arm's selected checkpoint scored lower. These are seed-level observations. Means
and sample standard deviations are descriptive summaries of four training/
partition seeds on UWF-ZeekData24, not a significance test or independent-data
generalization result.

| Seed | Gated loss | TPM-only loss | TPM minus gated |
|---:|---:|---:|---:|
"""
    loss_by_seed = {
        seed: {r["policy"]: r["paired_loss_clean_minus_adaptive"]
               for r in paired if r["seed"] == seed}
        for seed in SEEDS
    }
    for seed in SEEDS:
        gated = loss_by_seed[seed]["gated_composite"]
        tpm = loss_by_seed[seed]["tpm_only"]
        readme += f"| {seed} | {gated:+.6f} | {tpm:+.6f} | {tpm-gated:+.6f} |\n"
    readme += (
        f"\nMean gated loss: {means['gated_composite']['mean_loss']:+.6f} "
        f"(sample SD {means['gated_composite']['sample_sd_loss']:.6f}); "
        f"mean TPM-only loss: {means['tpm_only']['mean_loss']:+.6f} "
        f"(sample SD {means['tpm_only']['sample_sd_loss']:.6f}). "
        f"Mean TPM-minus-gated difference: {means['tpm_minus_gated_paired_loss']['mean_difference']:+.6f} "
        f"(sample SD {means['tpm_minus_gated_paired_loss']['sample_sd_difference']:.6f}).\n"
    )
    readme += """
## Interpretation limits

The 342593 result is an exploratory first observation; these additional
replications were planned after that outcome was known. All campaigns reuse the
same underlying dataset and existing IID partition pipeline. Seeds are the
replication unit; rounds, queries, and contribution decisions are not independent
samples. Do not describe these four seeds as a confirmatory study or claim
statistical significance.

The TPM-only adaptive checkpoint at seed 342593 was selected at round 10, before
the attack began in round 11. Its lower test score is not evidence that the
selected model contains a poisoned update. Read the per-seed selected rounds,
validation histories, admission denominators, and individual losses before drawing
a conclusion. The adaptive search met the predeclared validation criterion in
4/20 gated and 19/20 TPM-only attack rounds for seed 342593; replication outcomes
are shown separately above and in search-success.csv.

Admission percentages pool contribution decisions for visualization only. The
complete per-seed denominators and action counts are in admission-summary.csv.

![Paired test loss by seed](paired-loss-by-seed.png)

![Admission outcomes](admission-outcomes.png)

![Validation search success](search-success-by-seed.png)

See per-arm.csv, paired-losses.csv, rounds.csv, admission-summary.csv,
search-success.csv, and summary.json. Source completion and execution-lock hashes
are recorded in summary.json.
"""
    with (out / "README.md").open("x", encoding="utf-8", newline="") as stream:
        stream.write(readme)

    files = {
        path.name: sha(path)
        for path in sorted(out.iterdir())
        if path.is_file()
    }
    manifest = {
        "artifact_type": "m6_adaptive_untargeted_multiseed_report_manifest",
        "files": files,
        "summary_sha256": files["summary.json"],
        "source_receipts": summary["source_receipts"],
        "report_script_sha256": sha(Path(__file__)),
    }
    write_json(out / "manifest.json", manifest)
    print(json.dumps({
        "status": "reported",
        "seed_count": len(SEEDS),
        "paired_loss_means": {
            policy: data["mean_loss"] for policy, data in means.items()
            if policy in POLICIES
        },
        "output": str(out),
        "manifest_sha256": sha(out / "manifest.json"),
    }, indent=2))


if __name__ == "__main__":
    main()
