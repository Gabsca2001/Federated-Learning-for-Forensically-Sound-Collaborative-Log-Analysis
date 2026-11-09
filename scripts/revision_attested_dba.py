"""Fresh swtpm-backed live admission, bounded retraining and real M7 evidence.

The orchestrator never resets old TPMs. Each client sees only its own socket,
enrollment, partition, output and receipt-copy directory. Artifacts live in a new
versioned workspace; the image ID and all numeric/source digests are retained.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CLIENTS = [f"client{i:02d}" for i in range(1, 16)]
BRANCHES = ("baseline", "remove-client01-round1", "remove-client01-rounds1-3", "control")
ROUNDS = 5


def omitted(branch, number, client):
    return client == "client01" and (
        (branch == BRANCHES[1] and number == 1) or (branch == BRANCHES[2] and number in (1, 2, 3))
    )


CONFIG = Path("/app/configs/revision-dba-live-federation.yaml")
TRUST_CONFIG = Path("/app/configs/revision-dba-live-trust.yaml")
TCTI = "swtpm:path=/run/swtpm/swtpm.sock"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError(f"refuse to replace existing evidence: {path}")
    else:
        with path.open("xb") as stream:
            stream.write(data)


def internal(stage, branch, number):
    import torch

    torch.set_num_threads(1)
    root = Path("/evidence")
    partition = root / "partition"
    trust = root / "trust"
    campaign = root / "branches" / branch
    workspace = campaign / "rounds" / f"round-{number:03d}"
    validation = partition / "server/splits/validation.json"
    from fl_forensics.in_round_admission import (
        admit_and_aggregate_in_round,
        verify_in_round_secure_round,
    )
    from fl_forensics.secure_round import _coordinator_signer, initialize_secure_round
    from fl_forensics.storage import load_json
    from fl_forensics.tpm_adapter import verify_tpm2_quote
    from fl_forensics.trust import (
        enroll_nodes,
        initialize_trust_workspace,
        issue_challenges,
        verify_attestation_campaign,
    )

    if stage == "bootstrap":
        from fl_forensics.federated_partitioning import prepare_partitions, verify_partitions

        result = prepare_partitions(
            dataset_workspace=Path("/dataset"), output=partition, mode="iid", config_path=CONFIG
        )
        check = verify_partitions(workspace=partition, dataset_workspace=Path("/dataset"))
        assert check["status"] == "verified", check
        initialize_trust_workspace(
            workspace=trust,
            project_root=Path("/app"),
            trust_config_path=TRUST_CONFIG,
            clients_config_path=Path("/app/configs/clients.yaml"),
        )
        _coordinator_signer(root / "coordinator", create=True)
        for name in BRANCHES:
            shutil.copytree(root / "coordinator/authority", root / "branches" / name / "authority")
        import importlib.metadata as meta

        from fl_forensics.round_derivation import implementation_sha256

        save(
            root / "protocol.json",
            {
                "protocol": "swtpm-live-dba-bounded-replay-v1",
                "branches": BRANCHES,
                "rounds": ROUNDS,
                "intervention": {
                    "single_submission_branch": BRANCHES[1],
                    "single_submission_schedule": {"1": ["client01"]},
                    "explicit_set_branch": BRANCHES[2],
                    "explicit_set_schedule": {str(n): ["client01"] for n in (1, 2, 3)},
                    "clients_return": "all clients train in rounds 4 and 5; no permanent exclusion claim",
                    "identity_basis": "experiment ground truth supplied retrospectively; no detector claim",
                },
                "training": "train_local CPU, original Adam and deterministic per-round/per-client seed",
                "attestation": "fresh nonce and Quote for all clients before every branch/round",
                "tpm_profile": "swtpm (emulated TPM 2.0), no physical TPM available",
                "product_selection": "first two validation window IDs in lexicographic order, no label/metric selection",
                "attack_plan": json.loads(
                    Path("/app/configs/revision-dba-live-plan.json").read_bytes()
                ),
                "horizon_rationale": "three attack rounds plus two clean continuation rounds; mechanism case, not the separate 15-round efficacy benchmark",
                "evaluation": "all validation rows at every fixed round; complete and each component trigger; unchanged reference labels; no test access or outcome-based endpoint selection",
                "policy": "unchanged pinned in-round calibration; attack labels never enter scoring",
                "hypotheses": [
                    "structural dependency may persist without observed output changes",
                    "true subsequent retraining can differ from frozen-update reaggregation",
                    "attack acceptance and ASR improvement are outcomes, never assumptions",
                ],
                "source_implementation_sha256": implementation_sha256(),
                "environment": {
                    p: meta.version(p)
                    for p in ["torch", "numpy", "flwr", "pydantic", "cryptography", "scikit-learn"]
                },
                "dataset_manifest_sha256": sha("/dataset/manifest.json"),
                "partition_manifest_sha256": sha(partition / "manifest.json"),
                "training_config_sha256": sha(CONFIG),
                "trust_config_sha256": sha(TRUST_CONFIG),
                "partition_check": check,
                "partition_creation": result,
            },
        )
        return {"status": "bootstrapped"}
    if stage == "enroll":
        result = enroll_nodes(
            workspace=trust,
            node_root=root / "nodes",
            trust_config_path=TRUST_CONFIG,
            clients_config_path=Path("/app/configs/clients.yaml"),
        )
        index = load_json(trust / "registry/index.json")
        assert len(index["enrollments"]) == 15, result
        return result
    if stage == "challenge":
        return issue_challenges(
            workspace=trust, node_root=root / "nodes", trust_config_path=TRUST_CONFIG
        )
    if stage == "attest":
        result = verify_attestation_campaign(
            workspace=trust, node_root=root / "nodes", quote_verifier=verify_tpm2_quote
        )
        assert result["status"] == "verified", result
        save(root / "attestations" / f"{branch}-{number:03d}.json", result)
        return result
    if stage == "init":
        return initialize_secure_round(
            workspace=workspace,
            trust_workspace=trust,
            partition_manifest_path=partition / "manifest.json",
            config_path=CONFIG,
            secure_config_path=Path("/app/configs/secure-round.yaml"),
            coordinator_workspace=campaign,
            campaign_id="revision-attested-dba-20261103",
            round_number=number,
            previous_round_workspace=campaign / "rounds" / f"round-{number - 1:03d}"
            if number > 1
            else None,
            in_round_admission_config_path=Path("/app/configs/in-round-admission.yaml"),
            dba_training_config_path=Path("/app/configs/revision-dba-live-plan.json"),
        )
    if stage == "aggregate":
        receipts = root / "client-copies" / branch / f"round-{number:03d}"
        from fl_forensics.submission_evidence_workspace import create_submission_inventory_workspace

        inventory = root / "inventories" / branch / f"round-{number:03d}.json"
        intake = create_submission_inventory_workspace(
            workspace=workspace,
            trust_workspace=trust,
            client_receipts=receipts,
            submissions_root=workspace / "submissions",
            inventory_path=inventory,
            coordinator_workspace=campaign,
        )
        save(root / "reports" / f"{branch}-{number:03d}-intake.json", intake)
        result = admit_and_aggregate_in_round(
            workspace=workspace,
            trust_workspace=trust,
            submissions_root=workspace / "submissions",
            validation_split_path=validation,
            coordinator_workspace=campaign,
            client_receipts=receipts,
            input_inventory_path=inventory,
        )
        assert result["status"] == "aggregated", result
        save(root / "reports" / f"{branch}-{number:03d}-admission.json", result)
        return result
    if stage == "verify":
        result = verify_in_round_secure_round(
            workspace=workspace,
            trust_workspace=trust,
            submissions_root=workspace / "submissions",
            validation_split_path=validation,
            client_receipts=workspace / "client-receipts",
            require_derivation=True,
        )
        assert (
            result["status"] == "verified"
            and result["admission_decisions_verified"]
            and result["coefficients_verified"]
        ), result
        save(root / "reports" / f"{branch}-{number:03d}-verification.json", result)
        return result
    if stage == "campaign":
        from fl_forensics.secure_campaign import finalize_secure_campaign, verify_secure_campaign

        kw = {
            "workspace": campaign,
            "trust_workspace": trust,
            "partition_manifest_path": partition / "manifest.json",
            "server_evaluation_path": partition / "server/evaluation.json",
        }
        if not (campaign / "campaign-manifest.json").exists():
            result = finalize_secure_campaign(**kw, expected_rounds=ROUNDS)
            save(root / "reports" / f"{branch}-campaign-creation.json", result)
        check = verify_secure_campaign(**kw)
        assert check["status"] == "verified", check
        save(root / "reports" / f"{branch}-campaign-verification.json", check)
        return check
    if stage == "products":
        from fl_forensics.attack_mapping import (
            create_attack_mapping_bundle,
            verify_attack_mapping_bundle,
        )
        from fl_forensics.explanation_bundle import (
            create_explanation_bundle,
            verify_explanation_bundle,
        )
        from fl_forensics.investigation_report import (
            create_investigation_report_bundle,
            verify_investigation_report_bundle,
        )
        from fl_forensics.prediction_bundle import (
            create_prediction_bundle,
            verify_prediction_bundle,
        )

        dest = root / "products" / branch
        common = {
            "round_workspace": workspace,
            "trust_workspace": trust,
            "partition_workspace": partition,
            "dataset_workspace": Path("/dataset"),
        }
        pc = Path("/app/configs/investigation.yaml")
        ec = Path("/app/configs/investigation-explanations.yaml")
        ac = Path("/app/configs/investigation-attack.yaml")
        rc = Path("/app/configs/investigation-report.yaml")
        create_prediction_bundle(
            **common, output=dest / "prediction", config_path=pc, split="validation", first=2
        )
        checks = {
            "prediction": verify_prediction_bundle(
                **common, workspace=dest / "prediction", config_path=pc
            )
        }
        ex = {
            **common,
            "prediction_workspace": dest / "prediction",
            "prediction_config_path": pc,
            "config_path": ec,
        }
        create_explanation_bundle(**ex, output=dest / "explanation")
        checks["explanation"] = verify_explanation_bundle(**ex, workspace=dest / "explanation")
        at = {
            **common,
            "prediction_workspace": dest / "prediction",
            "explanation_workspace": dest / "explanation",
            "prediction_config_path": pc,
            "explanation_config_path": ec,
            "config_path": ac,
        }
        create_attack_mapping_bundle(**at, output=dest / "attack")
        checks["attack"] = verify_attack_mapping_bundle(**at, workspace=dest / "attack")
        re = {
            **common,
            "prediction_workspace": dest / "prediction",
            "explanation_workspace": dest / "explanation",
            "attack_workspace": dest / "attack",
            "prediction_config_path": pc,
            "explanation_config_path": ec,
            "attack_config_path": ac,
            "config_path": rc,
        }
        create_investigation_report_bundle(**re, output=dest / "report")
        checks["report"] = verify_investigation_report_bundle(**re, workspace=dest / "report")
        assert all(x.get("status") == "verified" for x in checks.values()), checks
        save(root / "reports" / f"{branch}-products.json", checks)
        return checks
    if stage == "graph":
        from fl_forensics.campaign_derivation import (
            create_campaign_derivation,
            structural_blast_radius,
            verify_campaign_derivation,
        )
        from fl_forensics.crypto import load_public_key

        rounds = {
            sha(p): p.parent.parent
            for p in (root / "branches").glob("*/rounds/round-*/derivation/manifest.json")
        }
        products = {sha(p): p.parent for p in (root / "products").glob("*/*/manifest.json")}
        signer = _coordinator_signer(root / "coordinator", create=False)
        common = {
            "round_workspaces": rounds,
            "product_workspaces": products,
            "coordinator_public_key": load_public_key(signer.public_pem()),
            "authority_public_key": load_public_key(signer.public_pem()),
        }
        result = create_campaign_derivation(output=root / "graph", signer=signer, **common)
        check = verify_campaign_derivation(
            workspace=root / "graph", expected_sha256=result["manifest_sha256"], **common
        )
        assert check["status"] == "verified", check
        source = load_json(root / "branches/baseline/rounds/round-001/derivation/manifest.json")
        sid = next(
            x["submission_id"]
            for x in source["core"]["dispositions"]
            if x["client_id"] == "client01"
        )
        radius = structural_blast_radius(
            workspace=root / "graph",
            expected_sha256=result["manifest_sha256"],
            submission_id=sid,
            **common,
        )
        save(root / "reports/graph.json", check)
        save(root / "reports/blast-radius.json", radius)
        return {"graph": result, "verification": check, "blast_radius": radius}
    if stage == "analysis":
        from revision_attested_dba_analysis import analyze

        return analyze(root)
    if stage == "compare":
        import numpy as np

        from fl_forensics.federated_model import arrays_from_export

        results = []
        for n in range(1, ROUNDS + 1):
            paths = [
                root / "branches" / b / "rounds" / f"round-{n:03d}" / "checkpoint/global-model.json"
                for b in BRANCHES
            ]
            assert paths[0].read_bytes() == paths[3].read_bytes(), (
                f"negative control differs at {n}"
            )
            a, b = [arrays_from_export(load_json(p), np=np) for p in paths[:2]]
            distance = float(
                np.linalg.norm(
                    np.concatenate(
                        [(x - y).ravel().astype(np.float64) for x, y in zip(a, b, strict=True)]
                    )
                )
            )
            results.append(
                {
                    "round": n,
                    "baseline_model_sha256": sha(paths[0]),
                    "intervention_model_sha256": sha(paths[1]),
                    "control_model_sha256": sha(paths[3]),
                    "parameter_l2": distance,
                    "negative_control_identical": True,
                }
            )
        save(root / "reports/numerical-comparison.json", results)
        return {"status": "verified", "rounds": results}
    raise ValueError(stage)


def host(args):
    root = Path(__file__).resolve().parents[1]
    lab = (root / args.workspace).resolve()
    assert lab.is_relative_to(root / "artifacts")
    lab.mkdir(parents=True, exist_ok=True)
    log = lab / "logs"
    log.mkdir(exist_ok=True)
    uid = f"{os.getuid()}:{os.getgid()}"
    image = args.image

    def docker(arguments, name):
        with (log / f"{name}.txt").open("ab") as stream:
            p = subprocess.run(
                ["docker", *arguments],
                cwd=root,
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=False,
            )
        if p.returncode:
            raise RuntimeError(f"{name} failed with {p.returncode}; see {log / name}")

    def runtime(mounts, arguments, name):
        docker(
            [
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--user",
                uid,
                "--tmpfs",
                "/tmp:rw,size=512m",
                *mounts,
                image,
                *arguments,
            ],
            name,
        )

    full = [
        "-v",
        f"{lab}:/evidence",
        "-v",
        f"{root / 'artifacts/m2-data24-parquet'}:/dataset:ro",
    ]

    def stage(which, branch="baseline", n=1):
        runtime(
            full,
            [
                "/app/scripts/revision_attested_dba.py",
                "--stage",
                which,
                "--branch",
                branch,
                "--round",
                str(n),
            ],
            f"{branch}-{n:03d}-{which}",
        )
        print(f"{which} {branch} {n}", flush=True)

    def client(which, c, branch="baseline", n=1):
        node = lab / "nodes" / c
        node.mkdir(parents=True, exist_ok=True)
        socket = lab / "tpm-sockets" / c
        socket.mkdir(parents=True, exist_ok=True)
        mounts = ["-v", f"{node}:/runtime", "-v", f"{socket}:/run/swtpm"]
        common = ["-m", "fl_forensics"]
        if which == "provision":
            command = [
                "m4-tpm-provision",
                "--workspace",
                "/runtime",
                "--project-root",
                "/app",
                "--config",
                str(TRUST_CONFIG),
                "--client-id",
                c,
                "--node-id",
                c.replace("client", "node"),
                "--tpm-instance",
                c.replace("client", "tpm"),
                "--tcti",
                TCTI,
                "--trust-level",
                "swtpm",
            ]
        elif which == "quote":
            command = ["m4-tpm-quote", "--workspace", "/runtime", "--tcti", TCTI]
        else:
            rw = lab / "branches" / branch / "rounds" / f"round-{n:03d}"
            dest = rw / "submissions" / c
            dest.mkdir(parents=True, exist_ok=True)
            receipts = lab / "client-copies" / branch / f"round-{n:03d}" / c
            receipts.mkdir(parents=True, exist_ok=True)
            mounts += [
                "-v",
                f"{lab / 'partition/clients' / c}:/client:ro",
                "-v",
                f"{rw / 'public'}:/campaign/public:ro",
                "-v",
                f"{dest}:/submission",
                "-v",
                f"{receipts}:/client-receipts",
            ]
            command = [
                "m5-client-update",
                "--public-workspace",
                "/campaign/public",
                "--client-dataset",
                "/client/dataset.json",
                "--client-manifest",
                "/client/manifest.json",
                "--node-workspace",
                "/runtime",
                "--submission-workspace",
                "/submission",
                "--client-id",
                c,
                "--tcti",
                TCTI,
                "--client-receipt-root",
                "/client-receipts",
            ]
        runtime(mounts, [*common, *command], f"{branch}-{n:03d}-{c}-{which}")

    def parallel(action, clients):
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(action, clients))

    if not (lab / "protocol.json").exists():
        stage("bootstrap")
    containers = []
    try:
        if not (lab / "trust/registry/index.json").exists():
            raise ValueError("missing trust init")
        index = json.loads((lab / "trust/registry/index.json").read_text())
        for c in CLIENTS:
            state = lab / "tpm-state" / c
            state.mkdir(parents=True, exist_ok=True)
            socket = lab / "tpm-sockets" / c
            socket.mkdir(parents=True, exist_ok=True)
            name = f"revision-dba-20261103-v1-{c}"
            exists = (
                subprocess.run(
                    ["docker", "inspect", name], capture_output=True, check=False
                ).returncode
                == 0
            )
            if exists:
                docker(["start", name], f"{c}-tpm-start")
            else:
                docker(
                    [
                        "run",
                        "-d",
                        "--name",
                        name,
                        "--network",
                        "none",
                        "--read-only",
                        "--cap-drop",
                        "ALL",
                        "--cap-add",
                        "FOWNER",
                        "--tmpfs",
                        "/tmp:rw,size=16m",
                        "-v",
                        f"{state}:/var/lib/swtpm",
                        "-v",
                        f"{socket}:/run/swtpm",
                        "--entrypoint",
                        "/bin/sh",
                        image,
                        "/app/scripts/run_swtpm.sh",
                    ],
                    f"{c}-tpm-start",
                )
            containers.append(name)
        parallel(lambda c: client("provision", c), CLIENTS)
        if not index["enrollments"]:
            stage("enroll")
        for b in BRANCHES:
            for n in range(1, ROUNDS + 1):
                rw = lab / "branches" / b / "rounds" / f"round-{n:03d}"
                if not (rw / "checkpoint/manifest.json").exists():
                    if not (rw / "public/round-context.json").exists():
                        stage("challenge", b, n)
                        parallel(lambda c, b=b, n=n: client("quote", c, b, n), CLIENTS)
                        stage("attest", b, n)
                        stage("init", b, n)
                    selected = [c for c in CLIENTS if not omitted(b, n, c)]
                    parallel(lambda c, b=b, n=n: client("train", c, b, n), selected)
                    collector = lab / "client-copies" / b / f"round-{n:03d}"
                    if not (rw / "client-receipts").exists():
                        shutil.copytree(collector, rw / "client-receipts")
                    stage("aggregate", b, n)
                stage("verify", b, n)
        for b in BRANCHES:
            stage("campaign", b, ROUNDS)
        stage("compare")
        for b in BRANCHES[:3]:
            if not (lab / "reports" / f"{b}-products.json").exists():
                stage("products", b, ROUNDS)
        stage("graph")
        stage("analysis")
        image_meta = subprocess.check_output(["docker", "image", "inspect", image], text=True)
        save(lab / "runtime-image.json", json.loads(image_meta))
        print("LIVE CHAIN COMPLETED", flush=True)
    finally:
        for name in containers:
            docker(["stop", name], f"{name}-stop")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--stage")
    p.add_argument("--branch", default="baseline")
    p.add_argument("--round", type=int, default=1)
    p.add_argument("--image", default="revision-attested-dba:20261103-v1")
    p.add_argument("--workspace", default="artifacts/revision-attested-dba-v1")
    args = p.parse_args()
    if args.stage:
        print(
            json.dumps(internal(args.stage, args.branch, args.round), indent=2, allow_nan=False),
            flush=True,
        )
    else:
        host(args)


if __name__ == "__main__":
    main()
