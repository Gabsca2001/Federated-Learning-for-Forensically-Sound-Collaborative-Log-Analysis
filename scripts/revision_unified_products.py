"""Consolidate a fresh witnessed round into real M7 and a new M8 profile.

The original WSL remains the working repository. Public evidence is copied
without private keys; this publisher is retained separately, not TPM-measured.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
IMAGE = "revision-unified-chain:20261105-v1"
CASE = "unified-nominal"


def internal(stage):
    import torch

    torch.set_num_threads(1)
    from fl_forensics.canonical import sha256_file
    from fl_forensics.checkpoint_verification import verification_arguments
    from fl_forensics.storage import load_json, write_json_once

    public = Path("/public")
    partition = public / "partition"
    trust = public / "trust"
    campaign = public / "campaign"
    configs = public / "configs"
    workspace = campaign / "rounds/round-001"
    products = public / "products"
    pc = configs / "prediction.yaml"
    ec = configs / "explanation.yaml"
    ac = configs / "attack.yaml"
    rc = configs / "report.yaml"
    common = {
        "round_workspace": workspace,
        "trust_workspace": trust,
        "partition_workspace": partition,
        "dataset_workspace": public / "dataset",
    }

    if stage == "finalize":
        from fl_forensics.secure_campaign import finalize_secure_campaign, verify_secure_campaign

        actual = Path("/campaign")
        args = dict(
            workspace=actual,
            trust_workspace=trust,
            partition_manifest_path=partition / "manifest.json",
            server_evaluation_path=partition / "server/evaluation.json",
            **verification_arguments(configs / "checkpoint.yaml"),
        )
        if not (actual / "campaign-manifest.json").exists():
            finalize_secure_campaign(**args, expected_rounds=1)
        result = verify_secure_campaign(**args)
        assert result["status"] == "verified", result
        return result
    if stage == "prediction":
        from fl_forensics.prediction_bundle import (
            create_prediction_bundle,
            verify_prediction_bundle,
        )

        dest = products / "prediction"
        if not (dest / "manifest.json").exists():
            create_prediction_bundle(
                **common, output=dest, config_path=pc, split="validation", first=2
            )
        result = verify_prediction_bundle(**common, workspace=dest, config_path=pc)
    elif stage == "explanation":
        from fl_forensics.explanation_bundle import (
            create_explanation_bundle,
            verify_explanation_bundle,
        )

        args = dict(
            **common,
            prediction_workspace=products / "prediction",
            prediction_config_path=pc,
            config_path=ec,
        )
        dest = products / "explanation"
        if not (dest / "manifest.json").exists():
            create_explanation_bundle(**args, output=dest)
        result = verify_explanation_bundle(**args, workspace=dest)
    elif stage == "attack":
        from fl_forensics.attack_mapping import (
            create_attack_mapping_bundle,
            verify_attack_mapping_bundle,
        )

        args = dict(
            **common,
            prediction_workspace=products / "prediction",
            explanation_workspace=products / "explanation",
            prediction_config_path=pc,
            explanation_config_path=ec,
            config_path=ac,
        )
        dest = products / "attack"
        if not (dest / "manifest.json").exists():
            create_attack_mapping_bundle(**args, output=dest)
        result = verify_attack_mapping_bundle(**args, workspace=dest)
    elif stage == "report":
        from fl_forensics.investigation_report import (
            create_investigation_report_bundle,
            verify_investigation_report_bundle,
        )

        args = dict(
            **common,
            prediction_workspace=products / "prediction",
            explanation_workspace=products / "explanation",
            attack_workspace=products / "attack",
            prediction_config_path=pc,
            explanation_config_path=ec,
            attack_config_path=ac,
            config_path=rc,
        )
        dest = products / "report"
        if not (dest / "manifest.json").exists():
            create_investigation_report_bundle(**args, output=dest)
        result = verify_investigation_report_bundle(**args, workspace=dest)
    elif stage == "graph":
        from fl_forensics.campaign_derivation import (
            create_campaign_derivation,
            structural_blast_radius,
            verify_campaign_derivation,
        )
        from fl_forensics.crypto import SoftwareECDSASigner, load_public_key

        signer = SoftwareECDSASigner.load(Path("/authority/round-coordinator.private.pem"))
        paths = [products / name for name in ("prediction", "explanation", "attack", "report")]
        args = {
            "round_workspaces": {sha256_file(workspace / "derivation/manifest.json"): workspace},
            "product_workspaces": {sha256_file(p / "manifest.json"): p for p in paths},
            "coordinator_public_key": load_public_key(signer.public_pem()),
            "authority_public_key": load_public_key(signer.public_pem()),
        }
        if not (public / "graph/manifest.json").exists():
            create_campaign_derivation(output=public / "graph", signer=signer, **args)
        expected = sha256_file(public / "graph/manifest.json")
        result = verify_campaign_derivation(
            workspace=public / "graph", expected_sha256=expected, **args
        )
        source = load_json(workspace / "derivation/manifest.json")
        sid = source["core"]["dispositions"][0]["submission_id"]
        radius = structural_blast_radius(
            workspace=public / "graph", expected_sha256=expected, submission_id=sid, **args
        )
        write_json_once(public / "graph/blast-radius.json", radius)
    elif stage == "chain":
        from fl_forensics.system_chain import verify_system_chain

        return verify_system_chain(public)
    elif stage == "m8":
        from fl_forensics.crypto import SoftwareECDSASigner
        from fl_forensics.unified_preservation import create_unified_preservation
        from fl_forensics.witness_time import RFC3161Provider

        signer = SoftwareECDSASigner.load(Path("/authority/round-coordinator.private.pem"))
        return create_unified_preservation(
            root=public,
            output=Path("/closure/m8"),
            signer=signer,
            timestamp_provider=RFC3161Provider("https://timestamp.sectigo.com/qualified"),
        )
    elif stage == "recover":
        from fl_forensics.unified_preservation import verify_unified_recovery

        pin = load_json(Path("/closure/pins.json"))["closure_sha256"]
        return verify_unified_recovery(
            archive_path=Path("/closure/m8/recovery.tar"), expected_closure_sha256=pin
        )
    else:
        raise ValueError(stage)
    assert result["status"] == "verified", result
    return result


def host(args):
    import yaml

    from fl_forensics.canonical import sha256_file
    from fl_forensics.round_derivation import implementation_sha256
    from fl_forensics.storage import load_json, write_json_once
    from fl_forensics.system_chain import SystemChainSpec

    lab = REPO / args.workspace
    assert load_json(lab / "summary.json")["status"] == "verified_external_TSA_live_round"
    assert (
        load_json(lab / "source-manifest.json")["implementation_sha256"] == implementation_sha256()
    )
    public = lab / "public-chain"
    logs = lab / "integration-logs"
    logs.mkdir(exist_ok=True)
    reports = lab / "integration-reports"
    reports.mkdir(exist_ok=True)
    original_round = lab / "cases" / CASE / "round"
    campaign = lab / "coordinator"
    archived_round = campaign / "rounds/round-001"
    if not archived_round.exists():
        shutil.copytree(original_round, archived_round)
    if not public.exists():
        public.mkdir(mode=0o700)
        shutil.copytree(REPO / "artifacts/m2-data24-parquet", public / "dataset")
        shutil.copytree(lab / "partition", public / "partition")
        shutil.copytree(lab / "public-witness", public / "witness")
        for part in ("registry", "baseline", "results"):
            shutil.copytree(lab / "trust" / part, public / "trust" / part)
        (public / "trust/authority").mkdir()
        for path in (lab / "trust/authority").glob("*.public.pem"):
            shutil.copyfile(path, public / "trust/authority" / path.name)
        shutil.copyfile(lab / "trust/manifest.json", public / "trust/manifest.json")
        configs = public / "configs"
        configs.mkdir()
        pins = load_json(lab / "public-witness/external-pins.json")
        reference = {
            "snapshot": "../witness/snapshot.json",
            "expected_policy_digest": pins["policy_digest"],
            "expected_closure_digest": pins["closure_digest"],
            "witness_public_key": "../witness/witness-public.pem",
            "coordinator_public_key": "../witness/coordinator-public.pem",
            "client_keys": "../witness/client-keys.json",
            "tsa_trust_store": "../witness/tsa-trust-store.pem",
            "acknowledgements": [
                "../witness/" + p.name for p in sorted((public / "witness").glob("*-ack.json"))
            ],
        }
        profile = {"profile": "closed-witness-live-round-v1", "rounds": {"1": reference}}
        write_json_once(configs / "checkpoint.yaml", profile)
        config = yaml.safe_load((REPO / "configs/investigation.yaml").read_text())
        config["checkpoint_verification"] = profile
        (configs / "prediction.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
        for name, source in [
            ("explanation", "investigation-explanations.yaml"),
            ("attack", "investigation-attack.yaml"),
            ("report", "investigation-report.yaml"),
        ]:
            shutil.copyfile(REPO / "configs" / source, configs / (name + ".yaml"))
        shutil.copytree(
            REPO / "src",
            public / "source/src",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        write_json_once(
            public / "source/manifest.json",
            {
                "implementation_sha256": implementation_sha256(),
                "files": {p.name: sha256_file(p) for p in (REPO / "src/fl_forensics").glob("*.py")},
            },
        )
        (public / "source/controllers").mkdir()
        shutil.copyfile(__file__, public / "source/controllers/revision_unified_products.py")
        shutil.copyfile(
            lab / "executed-host-controller.py",
            public / "source/controllers/revision_unified_chain.py",
        )
        write_json_once(
            public / "runtime.json",
            {
                "image_id": load_json(lab / "runtime-image.json")[0]["Id"],
                "implementation_sha256": implementation_sha256(),
                "publisher_controller_is_TPM_measured": False,
            },
        )
    scratch = lab / "scratch"
    scratch.mkdir(exist_ok=True)
    closure = lab / "final-closure"
    closure.mkdir(exist_ok=True)

    def stage(name, network="none"):
        marker = reports / (name + ".json")
        if marker.exists():
            print(json.dumps({"stage": name, "status": "retained_completed_stage"}), flush=True)
            return load_json(marker)
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--env",
            "TMPDIR=/scratch",
            "--tmpfs",
            "/tmp:rw,size=512m",
            "-v",
            str(public) + ":/public",
            "-v",
            str(campaign) + ":/campaign",
            "-v",
            str(campaign / "authority") + ":/authority:ro",
            "-v",
            str(scratch) + ":/scratch",
            "-v",
            str(closure) + ":/closure",
            "-v",
            str(Path(__file__).resolve()) + ":/controller.py:ro",
            IMAGE,
            "-u",
            "/controller.py",
            "--internal",
            name,
        ]
        write_json_once(logs / (name + "-command.json"), {"arguments": command})
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        (logs / (name + ".txt")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"{name} failed; inspect {logs / (name + '.txt')}")
        report = json.loads(result.stdout)
        write_json_once(marker, report)
        print(json.dumps({"stage": name, "status": report["status"]}), flush=True)
        return report

    stage("finalize")
    if not (public / "campaign").exists():
        shutil.copytree(
            campaign, public / "campaign", ignore=shutil.ignore_patterns("*.private.pem")
        )
    for name in ("prediction", "explanation", "attack", "report", "graph"):
        stage(name)
    if not (public / "system-chain.json").exists():
        spec = SystemChainSpec(
            dataset="dataset",
            partition="partition",
            trust="trust",
            campaign="campaign",
            witness_profile="configs/checkpoint.yaml",
            prediction="products/prediction",
            explanation="products/explanation",
            attack_mapping="products/attack",
            report="products/report",
            prediction_config="configs/prediction.yaml",
            explanation_config="configs/explanation.yaml",
            attack_config="configs/attack.yaml",
            report_config="configs/report.yaml",
            graph="graph",
            graph_manifest_sha256=sha256_file(public / "graph/manifest.json"),
            expected_rounds=1,
        )
        write_json_once(public / "system-chain.json", spec.model_dump(mode="json"))
    stage("chain")
    preserved = stage("m8", network="bridge")
    if not (closure / "pins.json").exists():
        write_json_once(
            closure / "pins.json",
            {
                "closure_sha256": preserved["closure_sha256"],
                "archive_sha256": preserved["archive_sha256"],
                "retained_by_local_operator": True,
                "independent_retention_demonstrated": False,
            },
        )
    recovered = stage("recover")
    write_json_once(
        lab / "unified-validation.json",
        {
            "status": "verified_unified_chain_and_recovery",
            "implementation_sha256": implementation_sha256(),
            "image_id": load_json(lab / "runtime-image.json")[0]["Id"],
            "rounds": 1,
            "clients": 15,
            "actual_software_TPM_signed_updates": 15,
            "external_registration_and_closure_tokens": 16,
            "external_M8_timestamp_tokens": 1,
            "M7_cases": 2,
            "all_M7_products_created_and_verified": True,
            "M8_recovery": recovered,
            "administrative_independence_demonstrated": False,
            "attack_resistance_evaluated": False,
            "source_record_coverage_replayed": False,
            "controller_TPM_measured": False,
            "thesis_edited": False,
        },
    )
    print(
        json.dumps({"status": "verified_unified_chain_and_recovery", "workspace": str(lab)}),
        flush=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--internal",
        choices=(
            "finalize",
            "prediction",
            "explanation",
            "attack",
            "report",
            "graph",
            "chain",
            "m8",
            "recover",
        ),
    )
    parser.add_argument("--workspace", default="artifacts/revision-unified-chain-20261105-v1")
    args = parser.parse_args()
    if args.internal:
        print(json.dumps(internal(args.internal)), flush=True)
    else:
        host(args)
