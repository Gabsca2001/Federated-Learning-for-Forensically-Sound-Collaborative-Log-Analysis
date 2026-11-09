"""Retrospective group hypotheses and conditional removal controls.

Candidate selection never receives attacker identities. Oracle attack membership
is used only afterwards to label evaluation and sample benign control groups.
"""

from __future__ import annotations

import argparse
import itertools
import json
import tempfile
from pathlib import Path

import numpy as np
import revision_dba_experiment as runner

from fl_forensics.byzantine import aggregate_deltas, apply_delta, model_delta, update_indicators
from fl_forensics.canonical import digest_object, sha256_file
from fl_forensics.composite_admission import decide_admission_policies, score_statistical_indicators
from fl_forensics.composite_admission_models import IndicatorReference, TrustSignal
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.retrospective_groups import calibrate_groups, detect_groups
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.storage import write_once


def load_rounds(root):
    values = []
    for path in sorted((root / "rounds").glob("round-*/round.json")):
        record = json.loads(path.read_bytes())
        base = json.loads((path.parent / "base-model.json").read_bytes())
        arrays = arrays_from_export(base, np=np)
        deltas = [
            model_delta(
                arrays,
                arrays_from_export(
                    json.loads((path.parent / "updates" / f"{client}.json").read_bytes()), np=np
                ),
            )
            for client in record["client_ids"]
        ]
        indicators = json.loads((path.parent / "indicators.json").read_bytes())
        values.append(
            {
                "round_number": record["round_number"],
                "client_ids": record["client_ids"],
                "deltas": deltas,
                "indicators": indicators,
            }
        )
    return values


def analyze(candidate, candidate_pin, clean, clean_pin, output, comparison_round=None):
    runner.authenticate(candidate, candidate_pin)
    runner.authenticate(clean, clean_pin)
    output.mkdir(exist_ok=False, parents=True)
    clean_rounds, candidate_rounds = load_rounds(clean), load_rounds(candidate)
    if comparison_round is not None:
        if comparison_round not in {record["round_number"] for record in candidate_rounds}:
            raise ValueError("comparison round is absent from the authenticated trajectory")
        clean_rounds = [
            record for record in clean_rounds if record["round_number"] <= comparison_round
        ]
        candidate_rounds = [
            record for record in candidate_rounds if record["round_number"] <= comparison_round
        ]
    calibration = calibrate_groups([clean_rounds])
    runner.save(output / "calibration-clean-only.json", calibration)
    hypotheses = detect_groups(candidate_rounds, calibration)
    # Make selection durable before consulting the experiment's ground-truth plan.
    runner.save(output / "candidate-groups-before-evaluation-labels.json", hypotheses)
    config = json.loads((candidate / "protocol-before-training.json").read_bytes())
    plan = runner.DistributedBackdoorPlan.model_validate(config["attack_plan"])
    truth = sorted(plan.client_components)
    clients = candidate_rounds[-1]["client_ids"]
    benign = sorted(set(clients) - set(truth))
    validation = runner.read_pinned(config["validation_path"], config["validation_sha256"])["rows"][
        "validation"
    ]
    deps = runner.dependencies()
    deps[1].set_num_threads(1)
    initial = runner.read_pinned(config["base_model_path"], config["base_model_sha256"])
    reference, _ = runner.predict(initial, validation, deps)
    correct = [
        row["label"] == predicted for row, predicted in zip(validation, reference, strict=True)
    ]
    last = candidate / "rounds" / f"round-{candidate_rounds[-1]['round_number']:03d}"
    record = json.loads((last / "round.json").read_bytes())
    base = json.loads((last / "base-model.json").read_bytes())
    base_arrays = arrays_from_export(base, np=np)
    models = [
        arrays_from_export(json.loads((last / "updates" / f"{client}.json").read_bytes()), np=np)
        for client in clients
    ]
    deltas = candidate_rounds[-1]["deltas"]
    counts = [item["metrics"]["num_examples"] for item in record["local_training_records"]]
    policy = json.loads((last / "calibration-and-decisions.json").read_bytes())
    refs = {
        name: IndicatorReference.model_validate(value)
        for name, value in policy["references"].items()
    }
    thresholds = policy["thresholds"]
    specs = runner.yaml.safe_load(Path(config["composite_config_path"]).read_bytes())
    weights = {name: value["weight"] for name, value in specs["statistics"]["indicators"].items()}
    trust = TrustSignal(
        raw_status="software-experiment-admissibility-assumption",
        admissible=True,
        risk=0,
        evaluated_checks=[],
        failed_checks=[],
        reasons=["Historical software admissibility assumption retained; no new attestation."],
    )
    impacts = {
        item["client_id"]: item["validation_impact"] for item in candidate_rounds[-1]["indicators"]
    }
    original_actions = {
        item["client_id"]: item["decision"]["status"] for item in policy["decisions"]
    }
    original_fedavg = json.loads((last / "aggregates/fedavg.json").read_bytes())
    original_fedavg_outcome = runner.outcomes(original_fedavg, validation, plan, correct, deps)
    original_gated_path = last / "aggregates/gated_composite.json"
    original_gated = (
        runner.outcomes(
            json.loads(original_gated_path.read_bytes()), validation, plan, correct, deps
        )
        if original_gated_path.exists()
        else None
    )
    evaluated = {}

    def removal(group):
        key = ",".join(sorted(group))
        if key in evaluated:
            return evaluated[key]
        remaining = [i for i, client in enumerate(clients) if client not in group]
        assert len(remaining) >= config["minimum_contributors"]
        frozen_arrays = apply_delta(
            base_arrays,
            aggregate_deltas(
                [deltas[i] for i in remaining],
                strategy="fedavg",
                weights=[counts[i] for i in remaining],
            ),
        )
        frozen = runner.model_with_arrays(base, frozen_arrays)
        indicators = update_indicators(
            [deltas[i] for i in remaining], client_ids=[clients[i] for i in remaining]
        )
        for item in indicators:
            item["validation_impact"] = impacts[item["client_id"]]
        signals = score_statistical_indicators(
            indicators, references=refs, weights=weights, z_cap=specs["statistics"]["robust_z_cap"]
        )
        masses, actions = [], {}
        for i in remaining:
            client = clients[i]
            decision = next(
                item
                for item in decide_admission_policies(
                    trust=trust,
                    statistics=signals[client],
                    statistical_threshold=thresholds["statistical_threshold"],
                    composite_threshold=thresholds["composite_threshold"],
                    composite_downweight_threshold=thresholds["composite_downweight_threshold"],
                    trust_weight=thresholds["trust_weight"],
                )
                if item.policy == "gated_composite"
            )
            actions[client] = decision.status
            masses.append(
                counts[i] * config["accepted_downweight_factor"]
                if decision.status == "accepted_downweighted"
                else counts[i]
                if decision.contributes
                else 0.0
            )
        surviving = [
            (models[i], mass) for i, mass in zip(remaining, masses, strict=True) if mass > 0
        ]
        frozen_outcome = runner.outcomes(frozen, validation, plan, correct, deps)
        rescore_outcome = None
        if len(surviving) >= config["minimum_contributors"]:
            rescore_model = runner.model_with_arrays(base, deps[4](surviving))
            rescore_outcome = runner.outcomes(rescore_model, validation, plan, correct, deps)
        value = {
            "removed_clients": sorted(group),
            "frozen_FedAvg": frozen_outcome,
            "rescore_gated": rescore_outcome,
            "survivor_action_change_fraction": sum(
                actions[client] != original_actions[client] for client in actions
            )
            / len(actions),
            "survivor_actions": actions,
            "frozen_FedAvg_ASR_reduction": original_fedavg_outcome["complete_trigger"]["asr"]
            - frozen_outcome["complete_trigger"]["asr"],
            "rescore_gated_ASR_reduction": original_gated["complete_trigger"]["asr"]
            - rescore_outcome["complete_trigger"]["asr"]
            if original_gated is not None and rescore_outcome is not None
            else None,
        }
        evaluated[key] = value
        return value

    groups = [("candidate", group) for group in hypotheses["candidate_groups"]]
    groups.append(("oracle-labelled-diagnostic-not-detector-output", truth))
    comparisons = []
    for role, group in groups:
        if len(clients) - len(group) < config["minimum_contributors"]:
            comparisons.append({"role": role, "clients": group, "status": "quorum-insufficient"})
            continue
        joint = removal(group)
        individuals = [removal([client]) for client in group]
        controls = list(itertools.combinations(benign, len(group)))
        rng = np.random.default_rng(341593 + len(group))
        selected = (
            [
                controls[i]
                for i in sorted(rng.choice(len(controls), min(20, len(controls)), replace=False))
            ]
            if controls
            else []
        )
        effects = [removal(list(control))["frozen_FedAvg_ASR_reduction"] for control in selected]
        comparisons.append(
            {
                "role": role,
                "clients": group,
                "oracle_attack_overlap_for_evaluation_only": sorted(set(group) & set(truth)),
                "joint": joint,
                "individuals": individuals,
                "joint_effect_minus_largest_individual_effect": joint["frozen_FedAvg_ASR_reduction"]
                - max(value["frozen_FedAvg_ASR_reduction"] for value in individuals),
                "benign_size_matched_control_groups": [list(group) for group in selected],
                "control_effects": effects,
                "control_effect_quantiles": np.quantile(effects, [0, 0.5, 0.95, 1]).tolist()
                if effects
                else None,
                "interpretation": "Conditional final-round interventions. Control ranks are descriptive and are not p-values or proof of intentional collusion.",
            }
        )
    report = {
        "candidate_manifest_sha256": candidate_pin,
        "clean_manifest_sha256": clean_pin,
        "group_detection": hypotheses,
        "comparison_round": candidate_rounds[-1]["round_number"],
        "interventions": comparisons,
        "unique_removals_evaluated": len(evaluated),
        "calibration_campaign_count": 1,
        "clean_calibration_pairs_not_independent": True,
        "future_retraining_performed": False,
        "validation_only": True,
        "intentional_collusion_proved": False,
        "scope": "Clean-calibrated exploratory group hypotheses; conditional frozen FedAvg and rescore-gated reaggregations. Oracle group is a separate labelled diagnostic.",
    }
    runner.save(output / "analysis.json", report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-pin", required=True)
    parser.add_argument("--clean", type=Path, required=True)
    parser.add_argument("--clean-pin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--comparison-round", type=int)
    args = parser.parse_args()
    report = analyze(
        args.candidate,
        args.candidate_pin,
        args.clean,
        args.clean_pin,
        args.output,
        args.comparison_round,
    )
    # Independent re-execution checks all numerical analysis outputs before closing.
    with tempfile.TemporaryDirectory(prefix="revision-groups-") as temporary:
        replay = Path(temporary) / "replay"
        analyze(
            args.candidate,
            args.candidate_pin,
            args.clean,
            args.clean_pin,
            replay,
            args.comparison_round,
        )
        expected = {
            p.relative_to(args.output).as_posix(): sha256_file(p)
            for p in args.output.rglob("*")
            if p.is_file()
        }
        assert expected == {
            p.relative_to(replay).as_posix(): sha256_file(p)
            for p in replay.rglob("*")
            if p.is_file()
        }
    signer = SoftwareECDSASigner.generate()
    write_once(args.output / "experiment-authority.public.pem", signer.public_pem())
    write_once(args.output / "producer-script.py", Path(__file__).read_bytes())
    core = {
        "domain": "retrospective-exploratory-group-analysis-v1",
        "source_candidate_sha256": args.candidate_pin,
        "source_clean_sha256": args.clean_pin,
        "implementation_sha256": implementation_sha256(),
        "artifacts": {
            p.relative_to(args.output).as_posix(): sha256_file(p)
            for p in args.output.rglob("*")
            if p.is_file()
        },
        "reaggregation_reexecuted": True,
    }
    digest = digest_object(core)
    runner.save(
        args.output / "manifest.json",
        {"core": core, "core_digest": digest, "signature": runner.signature(signer, digest)},
    )
    print(
        json.dumps(
            {
                "manifest_sha256": sha256_file(args.output / "manifest.json"),
                "candidate_groups": report["group_detection"]["candidate_groups"],
                "removals_evaluated": report["unique_removals_evaluated"],
                "reaggregation_reexecuted": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
