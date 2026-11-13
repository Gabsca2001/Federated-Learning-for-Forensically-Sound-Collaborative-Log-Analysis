"""Fresh software-TPM/witness case using actual external RFC3161 signatures.

Client and admission code use the already preserved CPU image unchanged.
The host controller is recorded separately; it is not claimed as TPM-measured.
The witness stays local: no independent-administrator claim follows.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from fl_forensics.canonical import sha256_file
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.secure_round_models import SecureRoundContext
from fl_forensics.storage import load_json, write_json_once
from fl_forensics.submission_witness_cli import export_enrollment_bindings, initialize_state

REPO = Path(__file__).resolve().parents[1]
CLIENTS = [f"client{i:02d}" for i in range(1, 16)]
IMAGE = "revision-witness-round:20261105-v2"
CASE = "external-sectigo"
TCTI = "swtpm:path=/run/swtpm/swtpm.sock"
TSA_URL = "https://timestamp.sectigo.com/qualified"
TSA_OID = "0.4.0.2023.1.1"
ROOT_SHA256 = "f871f8976b4068d700d5f281084b4a29eaf4b8f35743330ba062fab46f58c2ed"


def run(args):
    trust_bytes = args.tsa_trust_store.read_bytes()
    cert = x509.load_pem_x509_certificate(trust_bytes)
    if cert.fingerprint(hashes.SHA256()).hex() != ROOT_SHA256:
        raise ValueError("external root differs from provider-published SHA256 pin")
    root = (REPO / args.workspace).resolve()
    if not root.is_relative_to(REPO / "artifacts") or root.exists():
        raise ValueError("a fresh workspace inside artifacts is required")
    root.mkdir(parents=True, mode=0o700)
    logs = root / "logs"
    logs.mkdir()
    uid = f"{os.getuid()}:{os.getgid()}"

    def save(path, value):
        write_json_once(path, value)

    save(
        root / "protocol.json",
        {
            "profile": "external-tsa-witness-M5-v2",
            "client_count": 15,
            "rounds": 1,
            "local_epochs": 1,
            "primary_policy": "tpm_only",
            "TSA_URL": TSA_URL,
            "TSA_policy_OID": TSA_OID,
            "root_der_sha256": ROOT_SHA256,
            "registration_window_seconds": 450,
            "minimum_timestamp_request_spacing_seconds": 15,
            "witness_independent_administration_demonstrated": False,
            "legal_qualification_assessed": False,
            "institutional_acceptance": False,
            "host_controller_is_not_TPM_measured": True,
            "host_controller_sha256": sha256_file(Path(__file__)),
            "core_implementation_sha256": implementation_sha256(),
        },
    )
    shutil.copyfile(__file__, root / "executed-host-controller.py")
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

    def docker(command, name, json_output=False):
        save(logs / (name + "-command.json"), {"arguments": ["docker", *command]})
        result = subprocess.run(
            ["docker", *command], cwd=REPO, text=True, capture_output=True, check=False
        )
        (logs / (name + ".txt")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"{name} failed; inspect {logs / (name + '.txt')}")
        return json.loads(result.stdout) if json_output else result.stdout

    def runtime(mounts, command, name, json_output=False):
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
                IMAGE,
                *command,
            ],
            name,
            json_output,
        )

    def stage(which):
        mounts = [
            "-v",
            f"{root}:/evidence",
            "-v",
            f"{REPO / 'artifacts/m2-data24-parquet'}:/dataset:ro",
        ]
        result = runtime(
            mounts,
            ["/app/scripts/revision_witness_round.py", "--stage", which, "--case", CASE],
            which,
            True,
        )
        save(root / "reports" / (which + ".json"), result)
        print(json.dumps({"stage": which, "status": result.get("status")}), flush=True)

    def client(which, c):
        node = root / "nodes" / c
        node.mkdir(parents=True, exist_ok=True)
        mounts = ["-v", f"{node}:/runtime", "-v", f"{root / 'sockets' / c}:/run/swtpm"]
        if which == "provision":
            command = [
                "m4-tpm-provision",
                "--workspace",
                "/runtime",
                "--project-root",
                "/app",
                "--config",
                "/app/configs/revision-witness-trust.yaml",
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
            output = root / "client-outputs" / c
            copies = root / "client-copies" / c
            output.mkdir(parents=True)
            copies.mkdir(parents=True)
            mounts += [
                "-v",
                f"{root / 'partition/clients' / c}:/client:ro",
                "-v",
                f"{root / 'cases' / CASE / 'round/public'}:/campaign/public:ro",
                "-v",
                f"{output}:/submission",
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
        runtime(mounts, ["-m", "fl_forensics", *command], c + "-" + which)

    def parallel(which):
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda c: client(which, c), CLIENTS))

    def cli(*command):
        result = subprocess.run(
            [sys.executable, "-m", "fl_forensics.cli", *map(str, command)],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(f"{command[0]} failed: {result.stdout} {result.stderr}")
        return json.loads(result.stdout)

    containers = []
    witness = None
    try:
        stage("bootstrap")
        for c in CLIENTS:
            state = root / "tpm-state" / c
            socket = root / "sockets" / c
            state.mkdir(parents=True)
            socket.mkdir(parents=True)
            name = root.name.replace("revision-", "", 1) + "-" + c
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
                    IMAGE,
                    "/app/scripts/run_swtpm.sh",
                ],
                c + "-start",
            )
            containers.append(name)
        parallel("provision")
        stage("enroll")
        stage("challenge")
        parallel("quote")
        stage("attest")
        stage("init")
        workspace = root / "cases" / CASE / "round"
        public = root / "public-witness"
        public.mkdir()
        context_path = workspace / "public/round-context.json"
        coord = workspace / "public/round-coordinator.public.pem"
        context = SecureRoundContext.model_validate(load_json(context_path))
        cutoff = datetime.fromisoformat(context.core.issued_at) + timedelta(seconds=450)
        export = export_enrollment_bindings(
            context_path=context_path,
            trust_workspace=root / "trust",
            authority_public_key_path=root / "trust/authority/enrollment-authority.public.pem",
            coordinator_public_key_path=coord,
            output=public / "client-keys.json",
        )
        save(public / "enrollment-bindings.json", export)
        state = root / "private-witness"
        initialized = initialize_state(
            state=state,
            context_path=context_path,
            coordinator_public_key_path=coord,
            client_keys_path=public / "client-keys.json",
            tsa_trust_store_path=args.tsa_trust_store,
            tsa_url=TSA_URL,
            tsa_policy_oid=TSA_OID,
            registration_deadline=cutoff.isoformat(),
        )
        for name in (
            "policy.json",
            "witness-public.pem",
            "coordinator-public.pem",
            "tsa-trust-store.pem",
            "context.json",
        ):
            shutil.copyfile(state / name, public / name)
        save(
            public / "pre-training-policy-pin.json",
            {
                "policy_digest": initialized["policy_digest"],
                "pinned_at": datetime.now(UTC).isoformat(),
                "clients": CLIENTS,
                "local_retention_only": True,
            },
        )
        service_log = (logs / "witness-service.txt").open("w+")
        witness = subprocess.Popen(
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
            if witness.poll() is not None:
                raise RuntimeError("witness exited before readiness")
            time.sleep(0.1)
        if not url:
            raise RuntimeError("witness readiness timeout")
        parallel("train")
        print(json.dumps({"stage": "trained", "TPM_signed_updates": 15}), flush=True)
        common = [
            "--expected-policy-digest",
            initialized["policy_digest"],
            "--witness-public-key",
            public / "witness-public.pem",
            "--coordinator-public-key",
            public / "coordinator-public.pem",
            "--client-keys",
            public / "client-keys.json",
            "--tsa-trust-store",
            public / "tsa-trust-store.pem",
        ]
        last_request = None
        for c in CLIENTS:
            if last_request is not None:
                while time.monotonic() - last_request < 15.1:
                    time.sleep(0.2)
            last_request = time.monotonic()
            receipt = next((root / "client-copies" / c).glob("*.json"))
            result = cli(
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
            last_request = time.monotonic()
            save(root / "reports" / (c + "-registration.json"), result)
            if result["eligibility"] != "eligible":
                raise RuntimeError(f"{c} did not register within the authenticated window")
            print(json.dumps({"stage": "external-registration", "client": c, **result}), flush=True)
        while datetime.now(UTC) < cutoff + timedelta(seconds=20):
            time.sleep(0.2)
        if time.monotonic() - last_request < 15.1:
            raise RuntimeError("closure would violate provider request spacing")
        closed = cli("witness-close", "--state", state, "--output", public / "snapshot.json")
        save(
            public / "external-pins.json",
            {
                "policy_digest": initialized["policy_digest"],
                "closure_digest": closed["closure_digest"],
                "retained_by_local_operator": True,
                "independent_witness_administration": False,
            },
        )
        witness.terminate()
        witness.wait(timeout=10)
        witness = None
        service_log.close()
        mounts = [
            "-v",
            f"{workspace}:/round",
            "-v",
            f"{root / 'trust'}:/trust:ro",
            "-v",
            f"{root / 'coordinator/authority'}:/coordinator/authority:ro",
            "-v",
            f"{root / 'partition/server/splits/validation.json'}:/validation.json:ro",
            "-v",
            f"{root / 'client-outputs'}:/delivered:ro",
            "-v",
            f"{public}:/witness:ro",
        ]
        bound = [
            "--workspace",
            "/round",
            "--trust-workspace",
            "/trust",
            "--validation-split",
            "/validation.json",
            "--snapshot",
            "/witness/snapshot.json",
            "--expected-policy-digest",
            initialized["policy_digest"],
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
        for c in CLIENTS:
            bound += ["--acknowledgement", "/witness/" + c + "-ack.json"]
        result = runtime(
            mounts,
            [
                "-m",
                "fl_forensics",
                "witness-round-admit",
                *bound,
                "--submissions-root",
                "/delivered",
                "--coordinator-workspace",
                "/coordinator",
            ],
            "admission",
            True,
        )
        if (
            result["status"] != "verified_witness_round"
            or result["round_verification"]["accepted_count"] != 15
        ):
            raise RuntimeError(f"external witnessed admission did not verify: {result}")
        save(root / "reports/admission.json", result)
        offline = runtime(
            mounts, ["-m", "fl_forensics", "witness-round-verify", *bound], "offline", True
        )
        save(root / "reports/offline.json", offline)
        if offline["status"] != "verified_witness_round":
            raise RuntimeError("offline verification failed")
        save(
            root / "runtime-image.json", docker(["image", "inspect", IMAGE], "image-inspect", True)
        )
        summary = {
            "status": "verified_external_TSA_live_round",
            "eligible_receipts": 15,
            "accepted_contributions": 15,
            "actual_external_timestamp_tokens": 16,
            "external_TSA_signature_verification": True,
            "witness_process_stopped_for_verification": True,
            "witness_independent_administration_demonstrated": False,
            "institutional_acceptance": False,
            "core_implementation_sha256": implementation_sha256(),
        }
        save(root / "summary.json", summary)
        print(json.dumps(summary), flush=True)
    finally:
        if witness is not None and witness.poll() is None:
            witness.terminate()
            witness.wait(timeout=10)
        for name in containers:
            docker(["stop", name], name + "-stop")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tsa-trust-store", type=Path, required=True)
    parser.add_argument("--workspace", default="artifacts/revision-external-tsa-20261105-v2")
    run(parser.parse_args())
