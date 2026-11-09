"""Fresh 15-client Docker/swtpm witness-to-M5 protocol validation.

Two one-round cases isolate the new phase contract, not attack robustness.
One is nominal. The other withholds one payload, leaves one client
unregistered, registers another late and revokes one otherwise ready client.
No old TPM state, campaign, baseline, receipt or release is overwritten.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLIENTS = [f"client{i:02d}" for i in range(1, 16)]
TCTI = "swtpm:path=/run/swtpm/swtpm.sock"


def save(path, data):
    from fl_forensics.storage import write_json_once

    write_json_once(Path(path), data)


def internal(stage, case):
    import torch

    torch.set_num_threads(1)
    from fl_forensics.secure_round import _coordinator_signer, initialize_secure_round
    from fl_forensics.tpm_adapter import verify_tpm2_quote
    from fl_forensics.trust import (
        enroll_nodes,
        initialize_trust_workspace,
        issue_challenges,
        revoke_enrollment,
        verify_attestation_campaign,
    )

    root = Path("/evidence")
    trust = root / "trust"
    config = Path("/app/configs/revision-unified-federation.yaml")
    trust_config = Path("/app/configs/revision-unified-trust.yaml")
    if stage == "bootstrap":
        from fl_forensics.federated_partitioning import prepare_partitions, verify_partitions

        result = prepare_partitions(
            dataset_workspace=Path("/dataset"),
            output=root / "partition",
            mode="iid",
            config_path=config,
        )
        check = verify_partitions(workspace=root / "partition", dataset_workspace=Path("/dataset"))
        assert check["status"] == "verified", check
        initialize_trust_workspace(
            workspace=trust,
            project_root=Path("/app"),
            trust_config_path=trust_config,
            clients_config_path=Path("/app/configs/clients.yaml"),
        )
        _coordinator_signer(root / "coordinator", create=True)
        return {"status": "bootstrapped", "partition": result, "verification": check}
    if stage == "enroll":
        return enroll_nodes(
            workspace=trust,
            node_root=root / "nodes",
            trust_config_path=trust_config,
            clients_config_path=Path("/app/configs/clients.yaml"),
        )
    if stage == "challenge":
        return issue_challenges(
            workspace=trust, node_root=root / "nodes", trust_config_path=trust_config
        )
    if stage == "attest":
        result = verify_attestation_campaign(
            workspace=trust, node_root=root / "nodes", quote_verifier=verify_tpm2_quote
        )
        assert result["status"] == "verified", result
        return result
    if stage == "init":
        return initialize_secure_round(
            workspace=root / "cases" / case / "round",
            trust_workspace=trust,
            partition_manifest_path=root / "partition/manifest.json",
            config_path=config,
            secure_config_path=Path("/app/configs/secure-round.yaml"),
            coordinator_workspace=root / "coordinator",
            campaign_id="witness-phase-v2-" + case + "-20261105",
            in_round_admission_config_path=Path("/app/configs/revision-unified-admission.yaml"),
        )
    if stage == "revoke":
        return revoke_enrollment(
            workspace=trust,
            client_id="client12",
            reason="witness-phase negative control: registration does not override revocation",
        ).model_dump(mode="json")
    raise ValueError(stage)


def host(args):
    from fl_forensics.canonical import sha256_file
    from fl_forensics.crypto import load_public_key
    from fl_forensics.round_derivation import implementation_sha256
    from fl_forensics.secure_round_models import SecureRoundContext
    from fl_forensics.storage import load_json
    from fl_forensics.submission_witness import verify_policy
    from fl_forensics.submission_witness_cli import (
        _keys,
        _request,
        export_enrollment_bindings,
        initialize_state,
    )
    from fl_forensics.witness_models import WitnessPolicy

    root = (REPO / args.workspace).resolve()
    if not root.is_relative_to(REPO / "artifacts") or root.exists():
        raise ValueError("experiment needs a new workspace inside artifacts")
    root.mkdir(parents=True, mode=0o700)
    logs = root / "logs"
    logs.mkdir()
    save(
        root / "source-manifest.json",
        {
            "implementation_sha256": implementation_sha256(),
            "files": {
                p.relative_to(REPO).as_posix(): sha256_file(p)
                for p in sorted((REPO / "src/fl_forensics").glob("*.py"))
            },
        },
    )
    save(
        root / "protocol.json",
        {
            "profile": "witness_live_round_v1",
            "witness_policy": "v2",
            "cases": ["nominal", "negative-intake-trust"],
            "client_count": 15,
            "rounds_per_case": 1,
            "registration_window_seconds": args.registration_window_seconds,
            "local_epochs": 1,
            "primary_policy": "tpm_only",
            "minimum_contributors": 10,
            "device": "cpu",
            "TSA": "local development RFC3161; signed one-second accuracy",
            "independent_administration_validated": False,
            "external_TSA_validated": False,
            "purpose": "phase/inventory/admission validation, not a poisoning or accuracy benchmark",
        },
    )
    uid = f"{os.getuid()}:{os.getgid()}"

    def docker(cmd, name, capture=False):
        result = subprocess.run(
            ["docker", *cmd], cwd=REPO, text=True, capture_output=True, check=False
        )
        (logs / (name + ".txt")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"{name} failed; see {logs / (name + '.txt')}")
        return json.loads(result.stdout) if capture else result.stdout

    def runtime(mounts, command, name, capture=False):
        return docker(
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
                args.image,
                *command,
            ],
            name,
            capture,
        )

    full = ["-v", f"{root}:/evidence", "-v", f"{REPO / 'artifacts/m2-data24-parquet'}:/dataset:ro"]

    def stage(which, case="nominal"):
        result = runtime(
            full,
            ["/app/scripts/revision_witness_round.py", "--stage", which, "--case", case],
            case + "-" + which,
            True,
        )
        save(root / "reports" / f"{case}-{which}.json", result)
        print(
            json.dumps({"stage": which, "case": case, "status": result.get("status")}), flush=True
        )
        return result

    def parallel(action):
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(action, CLIENTS))

    def client(which, c, case="nominal"):
        node = root / "nodes" / c
        socket = root / "sockets" / c
        node.mkdir(parents=True, exist_ok=True)
        socket.mkdir(parents=True, exist_ok=True)
        mounts = ["-v", f"{node}:/runtime", "-v", f"{socket}:/run/swtpm"]
        if which == "provision":
            command = [
                "m4-tpm-provision",
                "--workspace",
                "/runtime",
                "--project-root",
                "/app",
                "--config",
                "/app/configs/revision-unified-trust.yaml",
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
            target = root / "cases" / case
            out = target / "client-outputs" / c
            copies = target / "client-copies" / c
            out.mkdir(parents=True)
            copies.mkdir(parents=True)
            mounts += [
                "-v",
                f"{root / 'partition/clients' / c}:/client:ro",
                "-v",
                f"{target / 'round/public'}:/campaign/public:ro",
                "-v",
                f"{out}:/submission",
                "-v",
                f"{copies}:/client-receipts",
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
        return runtime(mounts, ["-m", "fl_forensics", *command], case + "-" + c + "-" + which)

    # Local test TSA is deliberately separate from both client TPM and coordinator.
    sys.path.insert(0, str(REPO / "tests"))
    from test_witness_time import OID, make_local_tsa, reply

    private = root / "private"
    private.mkdir(mode=0o700)
    authority = make_local_tsa(private / "tsa")
    lock = threading.Lock()

    class TSAHandler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            query = self.rfile.read(int(self.headers["Content-Length"]))
            with lock:
                response = reply(authority, query)
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    tsa = ThreadingHTTPServer(("127.0.0.1", 0), TSAHandler)
    thread = threading.Thread(target=tsa.serve_forever, daemon=True)
    thread.start()
    containers = []
    case_records = {}
    witness_process = None
    try:
        stage("bootstrap")
        for c in CLIENTS:
            state = root / "tpm-state" / c
            socket = root / "sockets" / c
            state.mkdir(parents=True)
            socket.mkdir(parents=True)
            name = args.container_prefix + "-" + c
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
                    args.image,
                    "/app/scripts/run_swtpm.sh",
                ],
                c + "-start",
            )
            containers.append(name)
        parallel(lambda c: client("provision", c))
        stage("enroll")
        for case in ("nominal", "negative-intake-trust"):
            stage("challenge", case)
            parallel(lambda c, case=case: client("quote", c, case))
            stage("attest", case)
            stage("init", case)
            target = root / "cases" / case
            public = target / "public-witness"
            public.mkdir(parents=True)
            context_path = target / "round/public/round-context.json"
            context = SecureRoundContext.model_validate(load_json(context_path))
            cutoff = datetime.fromisoformat(context.core.issued_at) + timedelta(
                seconds=args.registration_window_seconds
            )
            coord = target / "round/public/round-coordinator.public.pem"
            authority_key = root / "trust/authority/enrollment-authority.public.pem"
            exported = export_enrollment_bindings(
                context_path=context_path,
                trust_workspace=root / "trust",
                authority_public_key_path=authority_key,
                coordinator_public_key_path=coord,
                output=public / "client-keys.json",
            )
            save(public / "enrollment-bindings-verification.json", exported)
            state = private / case
            initialized = initialize_state(
                state=state,
                context_path=context_path,
                coordinator_public_key_path=coord,
                client_keys_path=public / "client-keys.json",
                tsa_trust_store_path=private / "tsa/ca.pem",
                tsa_url=f"http://127.0.0.1:{tsa.server_port}",
                tsa_policy_oid=OID,
                registration_deadline=cutoff.isoformat(),
            )
            for name in (
                "policy.json",
                "witness-public.pem",
                "tsa-trust-store.pem",
                "coordinator-public.pem",
                "context.json",
            ):
                shutil.copyfile(state / name, public / name)
            policy = WitnessPolicy.model_validate(load_json(public / "policy.json"))
            verify_policy(
                policy=policy,
                context=context,
                expected_policy_digest=initialized["policy_digest"],
                witness_public_key=load_public_key((public / "witness-public.pem").read_bytes()),
                coordinator_public_key=load_public_key(coord.read_bytes()),
                client_public_keys=_keys(public / "client-keys.json"),
                trust_store=(public / "tsa-trust-store.pem").read_bytes(),
            )
            save(
                public / "pre-training-policy-pin.json",
                {
                    "policy_digest": policy.core_digest,
                    "authenticated_before_training_at": datetime.now(UTC).isoformat(),
                    "clients": CLIENTS,
                },
            )
            service_log = (logs / (case + "-witness-service.txt")).open("w+")
            witness_process = subprocess.Popen(
                [
                    sys.executable,
                    "-u",
                    "-m",
                    "fl_forensics.cli",
                    "witness-serve",
                    "--state",
                    str(state),
                    "--port",
                    "0",
                ],
                cwd=REPO,
                stdout=service_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            url = None
            for _ in range(150):
                service_log.flush()
                service_log.seek(0)
                for line in service_log.read().splitlines():
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event.get("status") == "listening":
                        url = f"http://127.0.0.1:{event['address'][1]}"
                if url:
                    break
                if witness_process.poll() is not None:
                    raise RuntimeError("witness exited")
                time.sleep(0.1)
            if not url:
                raise RuntimeError("witness startup timeout")
            parallel(lambda c, case=case: client("train", c, case))
            print(json.dumps({"stage": "trained", "case": case, "clients": 15}), flush=True)
            for c in CLIENTS:
                source = target / "client-outputs" / c
                dest = target / "delivered" / c
                dest.mkdir(parents=True)
                for name in ("bundle.json", "update.json", "metrics.json"):
                    if (
                        case == "negative-intake-trust"
                        and c == "client14"
                        and name == "metrics.json"
                    ):
                        continue
                    shutil.copyfile(source / name, dest / name)

            def cli(*command, expect=0):
                result = subprocess.run(
                    [sys.executable, "-m", "fl_forensics.cli", *map(str, command)],
                    cwd=REPO,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode != expect:
                    raise RuntimeError(f"{command[0]}: {result.stdout} {result.stderr}")
                return json.loads(result.stdout)

            common = [
                "--expected-policy-digest",
                policy.core_digest,
                "--witness-public-key",
                public / "witness-public.pem",
                "--coordinator-public-key",
                coord,
                "--client-keys",
                public / "client-keys.json",
                "--tsa-trust-store",
                public / "tsa-trust-store.pem",
            ]

            def register(
                c, target=target, common=common, public=public, context_path=context_path, url=url
            ):
                receipt = next((target / "client-copies" / c).glob("*.json"))
                return cli(
                    "witness-submit",
                    *common,
                    "--policy",
                    public / "policy.json",
                    "--context",
                    context_path,
                    "--url",
                    url,
                    "--receipt",
                    receipt,
                    "--output",
                    public / (c + "-ack.json"),
                )

            selected = (
                CLIENTS
                if case == "nominal"
                else [c for c in CLIENTS if c not in {"client13", "client15"}]
            )
            acks = {c: register(c) for c in selected}
            assert all(v["eligibility"] == "eligible" for v in acks.values()), acks
            print(
                json.dumps(
                    {
                        "stage": "registered",
                        "case": case,
                        "eligible": len(acks),
                        "cutoff": cutoff.isoformat(),
                    }
                ),
                flush=True,
            )
            while datetime.now(UTC) < cutoff + timedelta(seconds=2):
                time.sleep(0.2)
            if case == "negative-intake-trust":
                acks["client15"] = register("client15")
                assert acks["client15"]["eligibility"] == "late"
                stage("revoke", case)
            closed = cli("witness-close", "--state", state, "--output", public / "snapshot.json")
            fetched = _request(url + "/snapshot")
            assert fetched["closure"]["core_digest"] == closed["closure_digest"]
            save(
                public / "external-pins.json",
                {
                    "policy_digest": policy.core_digest,
                    "closure_digest": closed["closure_digest"],
                    "local_operator_retention_only": True,
                    "independent_administration_validated": False,
                },
            )
            # Wait out the signed closure accuracy interval; no invented admission time.
            time.sleep(2)
            witness_process.terminate()
            witness_process.wait(timeout=10)
            witness_process = None
            service_log.close()
            mounts = [
                "-v",
                f"{target / 'round'}:/round",
                "-v",
                f"{root / 'trust'}:/trust:ro",
                "-v",
                f"{root / 'coordinator/authority'}:/coordinator/authority:ro",
                "-v",
                f"{root / 'partition/server/splits/validation.json'}:/validation.json:ro",
                "-v",
                f"{target / 'delivered'}:/delivered:ro",
                "-v",
                f"{public}:/witness:ro",
            ]
            args_common = [
                "--workspace",
                "/round",
                "--trust-workspace",
                "/trust",
                "--validation-split",
                "/validation.json",
                "--snapshot",
                "/witness/snapshot.json",
                "--expected-policy-digest",
                policy.core_digest,
                "--expected-closure-digest",
                closed["closure_digest"],
                "--witness-public-key",
                "/witness/witness-public.pem",
                "--coordinator-public-key",
                "/witness/coordinator-public.pem",
                "--client-keys",
                "/witness/client-keys.json",
                "--tsa-trust-store",
                "/witness/tsa-trust-store.pem",
            ]
            for c in acks:
                args_common += ["--acknowledgement", "/witness/" + c + "-ack.json"]
            result = runtime(
                mounts,
                [
                    "-m",
                    "fl_forensics",
                    "witness-round-admit",
                    *args_common,
                    "--submissions-root",
                    "/delivered",
                    "--coordinator-workspace",
                    "/coordinator",
                ],
                case + "-admission",
                True,
            )
            assert result["status"] == "verified_witness_round", result
            expected = (15, 15, 15, 0) if case == "nominal" else (13, 12, 11, 1)
            observed = (
                result["eligible_receipt_count"],
                result["ready_payload_count"],
                result["round_verification"]["accepted_count"],
                result["round_verification"]["quarantined_count"],
            )
            assert observed == expected, (observed, expected)
            save(root / "reports" / (case + "-admission.json"), result)
            case_records[case] = (mounts, args_common)
            print(
                json.dumps(
                    {
                        "stage": "admitted",
                        "case": case,
                        "counts": observed,
                        "global_model_sha256": result["global_model_sha256"],
                    }
                ),
                flush=True,
            )
        tsa.shutdown()
        tsa.server_close()
        thread.join()
        for case, (mounts, args_common) in case_records.items():
            result = runtime(
                mounts,
                ["-m", "fl_forensics", "witness-round-verify", *args_common],
                case + "-offline-verification",
                True,
            )
            assert result["status"] == "verified_witness_round", result
            result.update(witness_and_TSA_stopped=True)
            save(root / "reports" / (case + "-offline-verification.json"), result)
        save(
            root / "runtime-image.json",
            docker(["image", "inspect", args.image], "image-inspect", True),
        )
        summary = {
            "status": "verified",
            "cases": list(case_records),
            "actual_swtpm_clients": 15,
            "actual_trained_signed_updates": 30,
            "registration_set_verified": True,
            "coverage_verified": True,
            "admission_decisions_verified": True,
            "coefficients_verified": True,
            "offline_after_service_shutdown": True,
            "independent_administration_validated": False,
            "external_TSA_validated": False,
            "source_implementation_sha256": implementation_sha256(),
        }
        save(root / "summary.json", summary)
        print(json.dumps(summary), flush=True)
    finally:
        if witness_process is not None and witness_process.poll() is None:
            witness_process.terminate()
            witness_process.wait(timeout=10)
        tsa.shutdown()
        tsa.server_close()
        for name in containers:
            docker(["stop", name], name + "-stop")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--stage")
    p.add_argument("--case", default="nominal")
    p.add_argument("--workspace", default="artifacts/revision-unified-round-20261105-v2")
    p.add_argument("--image", default="revision-unified-round:20261105-v2")
    p.add_argument("--container-prefix", default="revision-unified-20261105-v2")
    p.add_argument("--registration-window-seconds", type=int, default=120)
    a = p.parse_args()
    if not 30 <= a.registration_window_seconds <= 300:
        p.error("registration window must be 30..300 seconds")
    if a.stage:
        print(json.dumps(internal(a.stage, a.case)), flush=True)
    else:
        host(a)
