"""Audit recorded admission mechanisms without training or opening test rows.

This script rechecks coordinator signatures, digest bindings and deterministic
decisions. It does not re-appraise TPM Quotes, recompute indicators from tensors,
or replace full campaign verification. Counterfactual policies share frozen
signals; they are not independently trained defender trajectories.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

from fl_forensics.composite_admission import (
    decide_admission_policies,
    score_statistical_indicators,
    trust_signal_from_checks,
)
from fl_forensics.composite_admission_models import IndicatorReference, StatisticalSignal, TrustSignal
from fl_forensics.crypto import load_public_key, public_key_id, verify_digest_signature
from fl_forensics.preprocessing import derived_json_bytes


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def signed(value, key, numeric=False):
    if numeric:
        core = derived_json_bytes(value["core"])
    else:
        core = json.dumps(value["core"], sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode()
    digest = hashlib.sha256(core).hexdigest()
    signature = value["signature"]
    require(digest == value["core_digest"], "signed core digest mismatch")
    require(signature["key_id"] == public_key_id(key), "unexpected signing key")
    require(verify_digest_signature(key, digest, signature["value_b64"]), "invalid signature")


def policy_map(trust, stats, limits):
    return {d.policy: d for d in decide_admission_policies(
        trust=trust, statistics=stats,
        statistical_threshold=limits["statistical_threshold"],
        composite_threshold=limits["composite_threshold"],
        composite_downweight_threshold=limits["composite_downweight_threshold"],
        trust_weight=limits["trust_weight"],
    )}


def factor(status, rho):
    return Fraction(1) if status == "accepted" else rho if status == "accepted_downweighted" else Fraction(0)


def active_sources(root, anchors):
    path = root / "results/m6-active-policy-multiseed-v1/summary.json"
    anchors[str(path.relative_to(root))] = sha(path)
    summary = read(path)
    for seed in range(341593, 345594, 1000):
        for policy in ("gated_composite", "sequential"):
            for condition in ("clean", "disagreement"):
                phase = "pilot" if seed == 341593 else "multiseed"
                name = f"m6-policy-{phase}-{policy}-{condition}-s{seed}-v1"
                workspace = root / "artifacts" / name
                require(sha(workspace / "campaign-manifest.json") ==
                        summary["sources"][name]["manifest_sha256"], "published manifest pin mismatch")
                yield "controlled", seed, policy, condition, workspace


def adaptive_sources(root, anchors):
    path = root / "results/m6-adaptive-untargeted-multiseed-v1/summary.json"
    report_manifest = root / "results/m6-adaptive-untargeted-multiseed-v1/manifest.json"
    anchors[str(path.relative_to(root))] = sha(path)
    anchors[str(report_manifest.relative_to(root))] = sha(report_manifest)
    require(sha(path) == read(report_manifest)["summary_sha256"], "adaptive report mismatch")
    summary = read(path)
    for seed in range(342593, 345594, 1000):
        name = ("m6-adaptive-untargeted-paired-s342593-v1-continuation-v3" if seed == 342593
                else f"m6-adaptive-untargeted-paired-s{seed}-v1")
        workspace = root / "artifacts" / name
        pins = summary["source_receipts"][str(seed)]
        for filename, field in (("complete.json", "campaign_complete_sha256"),
                                ("execution-lock.json", "execution_lock_sha256")):
            require(sha(workspace / filename) == pins[field], "adaptive completion/lock mismatch")
        require(read(workspace / "complete.json")["status"] == "verified", "incomplete source")
        for arm in ("gated_clean", "gated_adaptive"):
            yield "adaptive", seed, "gated_composite", arm, workspace / arm


def group_for(study, condition, number, client, trust):
    if study == "controlled" and condition == "disagreement" and client in {"client02", "client03", "client04"}:
        return "controlled_trust_failure" if not trust.admissible else "trusted_attacked"
    if study == "adaptive" and condition == "gated_adaptive" and number >= 11 and client in {"client02", "client05", "client14"}:
        return "attacker_active"
    return "benign"


def run(root):
    anchors, sources, configurations = {}, {}, {}
    counters = defaultdict(Counter)
    rounds, examples = [], []
    totals = Counter()
    for study, seed, source_policy, condition, workspace in [*active_sources(root, anchors),
                                                          *adaptive_sources(root, anchors)]:
        mp = workspace / "campaign-manifest.json"
        manifest = read(mp)
        key_path = workspace / "authority/round-coordinator.public.pem"
        key = load_public_key(key_path.read_bytes())
        signed(manifest, key)
        sources[str(workspace.relative_to(root))] = {
            "manifest_sha256": sha(mp), "coordinator_public_key_sha256": sha(key_path),
            "manifest_pinned_by_prior_report": study == "controlled",
        }
        require(manifest["core"]["round_count"] == 30, "unexpected horizon")
        for rr in manifest["core"]["rounds"]:
            number = rr["round_number"]
            rw = workspace / f"rounds/round-{number:03d}"
            cp_path = rw / "checkpoint/manifest.json"
            require(sha(cp_path) == rr["checkpoint_sha256"], "checkpoint pin mismatch")
            cp = read(cp_path)
            signed(cp, key, numeric=True)
            totals["signature_checks"] += 1
            contract_path = rw / "public/in-round-admission-contract.json"
            require(sha(contract_path) == cp["core"]["admission_contract_sha256"], "contract pin mismatch")
            contract = read(contract_path)
            require(hashlib.sha256(derived_json_bytes(contract["core"])).hexdigest() ==
                    contract["core_digest"], "contract digest mismatch")
            core = contract["core"]
            require(core["primary_policy"] == source_policy, "incorrect deployed policy")
            limits = core["thresholds"]
            configurations[contract["core_digest"]] = {
                "source_policy": source_policy, "thresholds": limits,
                "factor": core["accepted_downweight_factor"],
                "calibration_sample_count": limits["clean_sample_count"],
            }
            refs = {v["name"]: IndicatorReference.model_validate(v) for v in core["indicator_references"]}
            bound = {v["decision_sha256"] for v in cp["core"]["accepted_inputs"]} | set(cp["core"]["quarantined_decision_sha256"])
            paths = sorted((rw / "in-round-decisions").glob("client*.json"))
            require(len(paths) == 15 and {sha(p) for p in paths} == bound, "decision inventory mismatch")
            evaluated = []
            for path in paths:
                record = read(path)
                signed(record, key, numeric=True)
                d = record["core"]
                require(d["campaign_id"] == manifest["core"]["campaign_id"] and
                        d["round_number"] == number and d["contract_digest"] == contract["core_digest"] and
                        d["context_id"] == cp["core"]["context_id"], "decision context mismatch")
                trust = TrustSignal.model_validate(d["trust"])
                recomputed_trust = trust_signal_from_checks(d["m5_checks"], raw_status=trust.raw_status,
                                        passed_with_warning_risk=core["passed_with_warning_risk"])
                require(recomputed_trust == trust, "trust/checks mismatch")
                stats = StatisticalSignal.model_validate(d["statistics"])
                indicators = {"client_id": d["client_id"], **{v.name: v.raw_value for v in stats.components}}
                rescored = score_statistical_indicators([indicators], references=refs,
                            weights=core["indicator_weights"], z_cap=core["robust_z_cap"])[d["client_id"]]
                require(rescored == stats, "recorded component normalization mismatch")
                decisions = policy_map(trust, stats, limits)
                require([v.model_dump(mode="json") for v in decisions.values()] == d["policy_decisions"],
                        "recorded policy vector mismatch")
                require(decisions[source_policy].model_dump(mode="json") == d["primary_decision"] and
                        decisions[source_policy].status == d["final_status"], "deployed decision mismatch")
                rho = Fraction(str(core["accepted_downweight_factor"]))
                mass = d["num_examples"] * factor(d["final_status"], rho)
                require(mass == Fraction(Decimal(d["effective_weight_decimal"])), "effective mass mismatch")
                group = group_for(study, condition, number, d["client_id"], trust)
                zero_names = [v.name for v in stats.components if v.component_risk == 0]
                same_support = decisions["sequential"].contributes == decisions["gated_composite"].contributes
                totals["decisions_recomputed"] += 1
                totals["signature_checks"] += 1
                totals["support_disagreements"] += int(not same_support)
                totals["trust_warning_decisions"] += int(trust.admissible and trust.risk > 0)
                totals["trust_failed_decisions"] += int(not trust.admissible)
                if trust.admissible and trust.risk == 0:
                    require(limits["composite_threshold"] == (1-limits["trust_weight"])*limits["statistical_threshold"],
                            "threshold scaling assumption not satisfied")
                    require(same_support, "unexpected support difference")
                for policy, decision in decisions.items():
                    c = counters[(study, source_policy, condition, seed, policy, group)]
                    c["total"] += 1
                    c[decision.status] += 1
                    c["zero_component"] += int(bool(zero_names))
                    c["zero_validation_component"] += int("validation_impact" in zero_names)
                    c["zero_component_retained"] += int(bool(zero_names) and decision.contributes)
                    c["all_positive_retained"] += int(not zero_names and decision.contributes)
                if group in {"trusted_attacked", "attacker_active"} and decisions["gated_composite"].contributes and len(examples) < 12:
                    examples.append({"source_decision": str(path.relative_to(root)), "decision_sha256": sha(path),
                                     "group": group, "risk": stats.risk, "zero_components": zero_names,
                                     "sequential_status": decisions["sequential"].status,
                                     "gated_status": decisions["gated_composite"].status})
                evaluated.append((d, group, decisions, rho))
            totals["rounds"] += 1
            attacker = lambda group: group in {"trusted_attacked", "attacker_active"}
            if not any(attacker(g) for _, g, _, _ in evaluated):
                continue
            shares = {}
            for policy in ("tpm_only", "sequential", "gated_composite"):
                masses = [(d["num_examples"]*factor(decisions[policy].status, rho), group)
                          for d, group, decisions, rho in evaluated]
                total = sum((mass for mass, _ in masses), Fraction())
                count = sum(mass > 0 for mass, _ in masses)
                defined = total > 0 and count >= core["minimum_contributors"]
                bad_mass = sum((mass for mass, group in masses if attacker(group)), Fraction())
                share = bad_mass / total if defined else None
                shares[policy] = share
                rounds.append({"study": study, "source_policy": source_policy, "condition": condition,
                               "seed": seed, "round": number, "evaluated_policy": policy,
                               "contributing_count": count, "aggregate_defined": defined,
                               "attacker_share": float(share) if share is not None else None,
                               "attacker_share_numerator": share.numerator if share is not None else None,
                               "attacker_share_denominator": share.denominator if share is not None else None})
            if shares["gated_composite"] is not None and shares["sequential"] is not None:
                suffix = "higher" if shares["gated_composite"] > shares["sequential"] else "lower" if shares["gated_composite"] < shares["sequential"] else "equal"
                totals[f"{study}_gated_attacker_share_{suffix}_than_sequential"] += 1
        totals["signature_checks"] += 1  # manifest
        print(f"Audited {workspace.name}: 450 decisions", flush=True)
    rows = [{"study": a, "source_policy": b, "condition": c, "seed": d,
             "evaluated_policy": e, "group": f, **{name: counts[name] for name in (
                 "total", "accepted", "accepted_downweighted", "statistically_quarantined", "trust_quarantined",
                 "zero_component", "zero_validation_component", "zero_component_retained", "all_positive_retained")}}
            for (a, b, c, d, e, f), counts in sorted(counters.items())]
    # Counts are descriptive repeated decisions. No test metrics or rows are opened.
    return {"artifact_type": "gate_mechanism_audit_v1", "totals": dict(totals),
            "report_anchors": anchors, "sources": sources, "configurations": configurations,
            "per_seed_counts": rows, "round_attacker_shares": rounds, "retained_attack_examples": examples,
            "verification_scope": {
                "coordinator_signatures_rechecked": True, "policy_decisions_recomputed": True,
                "component_normalization_recomputed": True, "raw_indicator_extraction_recomputed": False,
                "tpm_quotes_reappraised": False, "test_rows_accessed": False,
                "new_training_performed": False, "defender_adaptive_comparison": False,
                "adaptive_manifest_prior_report_pin": False,
                "key_trust": "Retained local coordinator public keys; their fingerprints are recorded here.",
            }}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    root = args.repo.resolve()
    output = args.output or root / "results/revision-gate-mechanism-audit-v1"
    payload = run(root)
    payload["implementation_sha256"] = {
        name: sha(root / name) for name in (
            "src/fl_forensics/composite_admission.py", "src/fl_forensics/composite_admission_models.py",
            "src/fl_forensics/in_round_admission.py", "src/fl_forensics/byzantine.py")}
    payload["audit_script_sha256"] = sha(Path(__file__))
    if args.verify:
        require(read(output / "summary.json") == payload, "audit report differs from full recomputation")
        print(json.dumps({"verified": True, **payload["totals"]}, indent=2))
        return
    require(not output.exists(), "preserve existing report: choose a new output directory")
    output.mkdir(parents=True)
    (output / "summary.json").write_text(json.dumps(payload, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    for name, rows in (("per-seed.csv", payload["per_seed_counts"]),
                       ("round-attacker-shares.csv", payload["round_attacker_shares"])):
        with (output / name).open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    print(json.dumps(payload["totals"], indent=2))


if __name__ == "__main__":
    main()
