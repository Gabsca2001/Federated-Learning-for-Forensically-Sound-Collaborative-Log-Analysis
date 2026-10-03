"""Independent verifier for the untargeted four-arm adaptive M6 campaign."""
import argparse
import json
from datetime import datetime
from pathlib import Path

from fl_forensics.canonical import sha256_file
from fl_forensics.crypto import load_public_key
from fl_forensics.in_round_admission import verify_in_round_secure_round
from fl_forensics.secure_round import (
    _load_context, _verify_signed, verify_secure_round,
)
from m6_adaptive_live_signing import verified_authorization
from m6_adaptive_untargeted_live_search import execute_live

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text())


def equal(actual, expected, message):
    if actual != expected:
        raise ValueError(message)


def verify(pair, arm, number):
    lock = read(pair / "execution-lock.json")
    plan = lock["plan"]
    if arm not in plan["arms"] or not 1 <= number <= plan["rounds"]:
        raise ValueError("Round outside frozen plan")
    for path, digest in lock["files"].items():
        equal(sha256_file(ROOT / path), digest, "Locked input changed: " + path)
    equal(lock["static_lock_sha256"],
          sha256_file(ROOT / "configs/m6-adaptive-untargeted-paired-s343593-v1.lock.json"),
          "Static lock changed")
    policy = plan["policy_by_arm"][arm]
    campaign = pair / arm
    source = campaign / "rounds" / f"round-{number:03d}"
    trust = ROOT / "artifacts" / (plan["trust_tag"] + "-trust")
    validation = ROOT / plan["partition"] / "server/splits/validation.json"
    context = _load_context(source / "public")
    coordinator_key = load_public_key(
        (source / "public/round-coordinator.public.pem").read_bytes()
    )
    if not _verify_signed(context, coordinator_key):
        raise ValueError("Invalid M5 signed context")
    campaign_pre = verified_authorization(
        campaign / "experiment-precommit.json", coordinator_key
    )
    equal(campaign_pre["arm"], arm, "Arm changed")
    equal(campaign_pre["policy"], policy, "Policy changed")
    equal(campaign_pre["execution_lock_sha256"],
          sha256_file(pair / "execution-lock.json"), "Campaign lock changed")

    pre = verified_authorization(source / "adaptive-precommit.json", coordinator_key)
    active = arm.endswith("_adaptive") and number in plan["attack_rounds"]
    equal(pre["artifact_type"], "adaptive_live_precommit", "Wrong round precommit")
    equal(pre["arm"], arm, "Round arm changed")
    equal(pre["policy"], policy, "Round policy changed")
    equal(pre["attack_active"], active, "Treatment status changed")
    equal(pre["context_digest"], context.core_digest, "Round context changed")
    equal(pre["execution_lock_sha256"], sha256_file(pair / "execution-lock.json"),
          "Round lock changed")
    equal(pre["numerical_runtime"], plan["numerical_runtime"],
          "Numerical runtime declaration changed")
    cfg = json.loads(pre["config_json"])
    equal(cfg, lock["attack_configs"][policy], "Attack configuration changed")
    equal(pre["validation_sha256"], sha256_file(validation),
          "Validation split changed")
    for path, digest in pre["code"].items():
        equal(sha256_file(ROOT / path), digest, "Round implementation changed: " + path)

    selected = None
    attackers = []
    if active:
        authorization = verified_authorization(
            source / "adaptive-selection.json", coordinator_key
        )
        equal(authorization["artifact_type"], "adaptive_live_selection",
              "Wrong adaptive authorization")
        equal(authorization["context_digest"], context.core_digest,
              "Authorization context changed")
        equal(authorization["precommit_sha256"],
              sha256_file(source / "adaptive-precommit.json"),
              "Authorization precommit changed")
        search = source / "adaptive-search"
        summary = read(search / "summary.json")
        equal(authorization["search_receipt_sha256"],
              sha256_file(search / "summary.json"), "Search receipt changed")
        selected = summary["selected_query"]
        equal(authorization["selected_query"], selected, "Selected query changed")
        attackers = cfg["attackers"] if selected is not None else []
        equal(set(authorization["clients"]), set(attackers),
              "Signed candidate set changed")
    elif ((source / "adaptive-selection.json").exists()
          or (source / "adaptive-search").exists()):
        raise ValueError("Unexpected adaptive treatment files")

    for index in range(1, 16):
        cid = f"client{index:02d}"
        proposal = source / "proposals" / cid
        submission = source / "submissions" / cid
        generated = datetime.fromisoformat(
            read(proposal / "bundle.json")["core"]["generated_at"].replace("Z", "+00:00")
        )
        if generated < datetime.fromisoformat(pre["created_at"]):
            raise ValueError("Client proposal predates signed precommit")
        if cid in attackers:
            binding = authorization["clients"][cid]
            equal(binding["proposal_bundle_sha256"],
                  sha256_file(proposal / "bundle.json"), "Original proposal changed")
            candidate = search / "queries" / f"{selected:03d}" / f"{cid}.json"
            candidate_digest = sha256_file(candidate)
            equal(binding["candidate_sha256"], candidate_digest,
                  "Selected candidate changed")
            equal(candidate_digest, sha256_file(submission / "update.json"),
                  "Signed update differs from candidate")
            provenance = read(submission / "metrics.json")["m6_adaptive_live"]
            equal(provenance["authorization_sha256"],
                  sha256_file(source / "adaptive-selection.json"),
                  "TPM-signed provenance authorization changed")
            equal(provenance["precommit_sha256"],
                  sha256_file(source / "adaptive-precommit.json"),
                  "TPM-signed provenance precommit changed")
            equal(provenance["search_receipt_sha256"],
                  sha256_file(search / "summary.json"),
                  "TPM-signed provenance search receipt changed")
            equal(provenance["original_bundle_sha256"],
                  sha256_file(proposal / "bundle.json"),
                  "TPM-signed source proposal changed")
        else:
            for name in ("bundle.json", "update.json", "metrics.json"):
                equal((proposal / name).read_bytes(), (submission / name).read_bytes(),
                      "Untreated proposal changed: " + cid)

    if policy == "gated_composite":
        result = verify_in_round_secure_round(
            workspace=source, trust_workspace=trust,
            submissions_root=source / "submissions",
            validation_split_path=validation,
        )
    else:
        result = verify_secure_round(
            workspace=source, trust_workspace=trust,
            submissions_root=source / "submissions",
        )
    equal(result["status"], "verified", "Official M5/M6 round verification failed")

    if active:
        selected_at = datetime.fromisoformat(
            read(source / "adaptive-selection.json")["core"]["selected_at"]
        )
        evaluated_at = datetime.fromisoformat(
            read(source / "adaptive-search-time.json")["evaluated_at"]
        )
        if not (datetime.fromisoformat(pre["created_at"])
                <= evaluated_at <= selected_at):
            raise ValueError("Search and selection chronology is invalid")
        execute_live(
            search, True, source=source, trust=trust, validation=validation,
            cfg=cfg, evaluation_time=evaluated_at,
        )
        expected_query = selected if selected is not None else 0
        equal(
            (source / "checkpoint/global-model.json").read_bytes(),
            (search / "queries" / f"{expected_query:03d}" / "aggregate.json").read_bytes(),
            "Observed aggregate differs from selected, policy-specific prediction",
        )

    if arm.endswith("_adaptive") and number < min(plan["attack_rounds"]):
        clean_arm = ("gated_clean" if policy == "gated_composite" else "tpm_clean")
        reference = (
            pair / clean_arm / "rounds" / f"round-{number:03d}"
            / "checkpoint/global-model.json"
        )
        equal(
            (source / "checkpoint/global-model.json").read_bytes(),
            reference.read_bytes(),
            "Pre-attack paired trajectories differ within policy",
        )
    print(json.dumps({
        "status": "verified", "arm": arm, "policy": policy, "round": number,
        "attack_active": active, "signed_adaptive_clients": len(attackers),
        "test_data_accessed": False,
    }), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pair", type=Path, required=True)
    parser.add_argument("--arm", required=True)
    parser.add_argument("--round", type=int, required=True)
    args = parser.parse_args()
    verify(args.pair.resolve(), args.arm, args.round)


if __name__ == "__main__":
    main()
