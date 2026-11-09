"""Run a local, real-RFC3161 integration case with a separate witness process.

Uses disposable software client keys and a disposable development TSA. There
is no TPM experiment, external CA claim or independent-administration claim.
Only public verification evidence is retained; private keys stay temporary.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))
import test_submission_evidence as receipt_examples
from test_witness_time import OID, make_local_tsa, reply

from fl_forensics.canonical import digest_object, sha256_file
from fl_forensics.secure_round_models import SecureRoundContext
from fl_forensics.storage import write_json_once, write_once


def run(output: Path) -> dict:
    output = output.resolve()
    if output.exists():
        raise FileExistsError("case output must be new")
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="fl-witness-private-") as private:
        private = Path(private)
        authority = make_local_tsa(private / "tsa")
        lock = threading.Lock()

        class TSAHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
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
        tsa_thread = threading.Thread(target=tsa.serve_forever, daemon=True)
        tsa_thread.start()
        case = receipt_examples.SubmissionEvidenceTests()
        case.setUp()
        process = None
        try:
            case.now = datetime.now(UTC)
            context = case._context()
            deadline = datetime.now(UTC) + timedelta(seconds=25)
            core = context.core.model_copy(update={"expires_at": deadline.isoformat()})
            digest = digest_object(core.model_dump(mode="json"))
            case.context = SecureRoundContext(
                context_id=f"round-context-{digest[:24]}",
                core=core,
                core_digest=digest,
                signature=case._signature(case.coordinator, digest),
            )
            case.receipts, case.bundle_paths = [], {}
            for client_id in case.signers:
                path, _ = case._bundle(client_id, variant=997)
                case.paths[client_id] = path
                receipt = case._receipt(path, client_id)
                case.receipts.append(receipt)
                destination = output / "submissions" / client_id
                destination.mkdir(parents=True)
                for name in ("bundle.json", "update.json", "metrics.json"):
                    shutil.copyfile(path.parent / name, destination / name)
                write_json_once(
                    output / f"{client_id}-receipt.json", receipt.model_dump(mode="json")
                )
            late_path, _ = case._bundle("client01", variant=998)
            late_receipt = case._receipt(late_path, "client01")
            write_json_once(output / "late-receipt.json", late_receipt.model_dump(mode="json"))
            write_json_once(output / "context.json", case.context.model_dump(mode="json"))
            write_once(output / "coordinator-public.pem", case.coordinator.public_pem())
            write_once(output / "tsa-trust-store.pem", authority["trust_store"])
            keys = {}
            for client_id, signer in case.signers.items():
                name = f"{client_id}-public.pem"
                write_once(output / name, signer.public_pem())
                keys[client_id] = name
            write_json_once(output / "client-keys.json", keys)

            events = []

            def cli(*args, expected=0):
                result = subprocess.run(
                    [sys.executable, "-m", "fl_forensics.cli", *map(str, args)],
                    cwd=REPO,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode != expected:
                    raise RuntimeError(
                        f"{args[0]} returned {result.returncode}: {result.stdout} {result.stderr}"
                    )
                data = json.loads(result.stdout)
                events.append({"command": args[0], "exit_code": result.returncode, "report": data})
                return data

            state = private / "witness-state"
            init = cli(
                "witness-init",
                "--state",
                state,
                "--context",
                output / "context.json",
                "--coordinator-public-key",
                output / "coordinator-public.pem",
                "--client-keys",
                output / "client-keys.json",
                "--tsa-trust-store",
                output / "tsa-trust-store.pem",
                "--tsa-url",
                f"http://127.0.0.1:{tsa.server_port}",
                "--tsa-policy-oid",
                OID,
            )
            for name in ("policy.json", "witness-public.pem"):
                shutil.copyfile(state / name, output / name)
            log = (private / "service.log").open("w+")
            process = subprocess.Popen(
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
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            address = None
            for _ in range(150):
                log.flush()
                log.seek(0)
                for line in log.read().splitlines():
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event.get("status") == "listening":
                        address = event["address"]
                if address:
                    break
                if process.poll() is not None:
                    raise RuntimeError("witness service exited before readiness")
                time.sleep(0.1)
            if address is None:
                raise RuntimeError("witness service readiness timeout")
            url = f"http://127.0.0.1:{address[1]}"
            common = [
                "--expected-policy-digest",
                init["policy_digest"],
                "--witness-public-key",
                output / "witness-public.pem",
                "--coordinator-public-key",
                output / "coordinator-public.pem",
                "--client-keys",
                output / "client-keys.json",
                "--tsa-trust-store",
                output / "tsa-trust-store.pem",
            ]
            submit = [
                "--url",
                url,
                "--policy",
                output / "policy.json",
                "--context",
                output / "context.json",
                *common,
            ]
            for client_id in case.signers:
                report = cli(
                    "witness-submit",
                    *submit,
                    "--receipt",
                    output / f"{client_id}-receipt.json",
                    "--output",
                    output / f"{client_id}-ack.json",
                )
                assert report["eligibility"] == "eligible", report
            print(
                json.dumps(
                    {
                        "phase": "timely_registrations_complete",
                        "waiting_until": deadline.isoformat(),
                    }
                ),
                flush=True,
            )
            while datetime.now(UTC) < deadline + timedelta(seconds=2):
                time.sleep(0.2)
            late = cli(
                "witness-submit",
                *submit,
                "--receipt",
                output / "late-receipt.json",
                "--output",
                output / "late-ack.json",
            )
            assert late["eligibility"] == "late", late
            closure = cli("witness-close", "--state", state, "--output", output / "snapshot.json")
            cli("witness-fetch", "--url", url, "--output", output / "fetched-snapshot.json")
            assert sha256_file(output / "snapshot.json") == sha256_file(
                output / "fetched-snapshot.json"
            )
            process.terminate()
            process.wait(timeout=10)
            log.close()
            tsa.shutdown()
            tsa.server_close()
            tsa_thread.join()
            verify = [
                *common,
                "--expected-closure-digest",
                closure["closure_digest"],
                "--snapshot",
                output / "snapshot.json",
                "--acknowledgement",
                output / "client01-ack.json",
                "--acknowledgement",
                output / "client02-ack.json",
                "--acknowledgement",
                output / "late-ack.json",
            ]
            offline = cli("witness-verify", *verify)
            assert offline["eligible_receipt_count"] == 2
            assert offline["excluded_receipt_counts"]["late"] == 1
            inventory = case._inventory()
            write_json_once(output / "inventory.json", inventory.model_dump(mode="json"))
            good = cli(
                "witness-verify",
                *verify,
                "--inventory",
                output / "inventory.json",
                "--submissions-root",
                output / "submissions",
            )
            omitted = case._resign(inventory, entries=inventory.core.entries[1:])
            write_json_once(output / "coordinator-omission.json", omitted.model_dump(mode="json"))
            bad = cli(
                "witness-verify",
                *verify,
                "--inventory",
                output / "coordinator-omission.json",
                "--submissions-root",
                output / "submissions",
                expected=1,
            )
            assert bad["deadline_verified"] and not bad["coverage_verified"]
            snapshot = json.loads((output / "snapshot.json").read_text())
            snapshot["registrations"] = snapshot["registrations"][1:]
            write_json_once(output / "truncated-snapshot.json", snapshot)
            truncated_args = list(verify)
            truncated_args[truncated_args.index("--snapshot") + 1] = (
                output / "truncated-snapshot.json"
            )
            truncated = cli("witness-verify", *truncated_args, expected=1)
            assert not truncated["registration_set_verified"]
            write_json_once(output / "cli-events.json", {"events": events})
            source = {
                str(p.relative_to(REPO)): sha256_file(p)
                for p in sorted((REPO / "src/fl_forensics").glob("*.py"))
            }
            write_json_once(output / "source-manifest.json", source)
            summary = {
                "status": "verified_local_integration",
                "profile": "independent_witness_rfc3161_v1",
                "actual_RFC3161_cryptographic_verification": True,
                "separate_witness_process": True,
                "offline_verification_after_services_stopped": True,
                "independent_administration_validated": False,
                "external_TSA_used": False,
                "local_development_CA": True,
                "TPM_campaign_performed": False,
                "private_keys_exported": False,
                "deadline": deadline.isoformat(),
                "policy_digest": init["policy_digest"],
                "closure_digest": closure["closure_digest"],
                "source_manifest_digest": digest_object(source),
                "registered_receipts": 3,
                "eligible_receipts": 2,
                "late_receipts": 1,
                "valid_inventory_verified": good["coverage_verified"],
                "coordinator_signed_omission_detected": not bad["coverage_verified"],
                "truncated_log_detected": not truncated["registration_set_verified"],
                "delivery_verified": False,
                "admission_decisions_verified": False,
            }
            write_json_once(output / "summary.json", summary)
            index = {
                str(p.relative_to(output)): sha256_file(p)
                for p in sorted(output.rglob("*"))
                if p.is_file()
            }
            write_json_once(output / "artifact-index.json", index)
            return summary
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            tsa.shutdown()
            tsa.server_close()
            tsa_thread.join()
            case.tearDown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output), indent=2))
