"""Persistent loopback-only demonstration; not independent administration.

Starts a local development TSA and the actual witness CLI in a separate
process. State stays private in WSL. The --stop operation checks both the
recorded process start time and command fingerprint before signalling it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))
import test_submission_evidence as receipt_examples
from test_witness_time import OID, make_local_tsa, reply

from fl_forensics.canonical import canonical_json_bytes, digest_object
from fl_forensics.secure_round_models import SecureRoundContext
from fl_forensics.storage import atomic_json, load_json, write_json_once, write_once
from fl_forensics.submission_witness import verify_registration
from fl_forensics.submission_witness_cli import initialize_state, open_store


def identity(pid):
    root = Path("/proc") / str(pid)
    return {
        "start_ticks": (root / "stat").read_text().split(") ", 1)[1].split()[19],
        "command_sha256": hashlib.sha256((root / "cmdline").read_bytes()).hexdigest(),
    }


def run(args):
    root = args.workspace.resolve()
    if args.stop:
        record = load_json(root / "process.json")
        try:
            current = identity(record["pid"])
        except FileNotFoundError:
            return {"status": "already_stopped"}
        if current != record["identity"]:
            raise ValueError("recorded process identity changed; refusing to signal it")
        os.kill(record["pid"], signal.SIGTERM)
        return {"status": "stop_requested_for_owned_demo"}
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (root / "process.json").exists():
        old = load_json(root / "process.json")
        try:
            if identity(old["pid"]) == old["identity"]:
                raise ValueError("this demo is already running")
        except FileNotFoundError:
            pass
    tsa_root = root / "private-development-tsa"
    tsa_root.mkdir(exist_ok=True, mode=0o700)
    if not (tsa_root / "openssl.cnf").exists():
        make_local_tsa(tsa_root)
    authority = {"config": tsa_root / "openssl.cnf"}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length < 65536:
                self.send_error(413)
                return
            with lock:
                response = reply(authority, self.rfile.read(length))
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    tsa = ThreadingHTTPServer(("127.0.0.1", args.tsa_port), Handler)
    thread = threading.Thread(target=tsa.serve_forever, daemon=True)
    thread.start()
    process = None
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    try:
        if not (root / "witness-state/settings.json").exists():
            case = receipt_examples.SubmissionEvidenceTests()
            case.setUp()
            try:
                case.now = datetime.now(UTC)
                context = case._context()
                core = context.core.model_copy(
                    update={
                        "expires_at": (
                            case.now + timedelta(seconds=args.window_seconds)
                        ).isoformat(),
                    }
                )
                digest = digest_object(core.model_dump(mode="json"))
                case.context = SecureRoundContext(
                    context_id=f"round-context-{digest[:24]}",
                    core=core,
                    core_digest=digest,
                    signature=case._signature(case.coordinator, digest),
                )
                write_json_once(root / "context.json", case.context.model_dump(mode="json"))
                write_once(root / "coordinator-public.pem", case.coordinator.public_pem())
                keys = {}
                for client_id, signer in case.signers.items():
                    filename = f"{client_id}-public.pem"
                    write_once(root / filename, signer.public_pem())
                    keys[client_id] = filename
                    path, _ = case._bundle(client_id, variant=302)
                    receipt = case._receipt(path, client_id)
                    write_json_once(
                        root / f"{client_id}-receipt.json", receipt.model_dump(mode="json")
                    )
                write_json_once(root / "client-keys.json", keys)
                initialize_state(
                    state=root / "witness-state",
                    context_path=root / "context.json",
                    coordinator_public_key_path=root / "coordinator-public.pem",
                    client_keys_path=root / "client-keys.json",
                    tsa_trust_store_path=tsa_root / "ca.pem",
                    tsa_url=f"http://127.0.0.1:{args.tsa_port}",
                    tsa_policy_oid=OID,
                )
            finally:
                case.tearDown()
        settings = load_json(root / "witness-state/settings.json")
        if settings["tsa_url"] != f"http://127.0.0.1:{args.tsa_port}":
            raise ValueError("restart must retain the initialized TSA port")
        log = (root / "witness-service.log").open("ab")
        process = subprocess.Popen(
            [
                sys.executable,
                "-u",
                "-m",
                "fl_forensics.cli",
                "witness-serve",
                "--state",
                str(root / "witness-state"),
                "--port",
                str(args.port),
            ],
            cwd=REPO,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        url = f"http://127.0.0.1:{args.port}"
        for _ in range(100):
            try:
                with urllib.request.urlopen(url + "/policy", timeout=1) as response:
                    remote = json.load(response)
                if remote["core_digest"] != settings["expected_policy_digest"]:
                    raise ValueError("listener is not the expected witness")
                break
            except OSError:
                if process.poll() is not None:
                    raise ValueError("witness process failed; inspect its own service log")
                time.sleep(0.1)
        else:
            raise ValueError("witness startup timeout")
        store = open_store(root / "witness-state")
        for client_id in ("client01", "client02"):
            receipt = load_json(root / f"{client_id}-receipt.json")
            request = urllib.request.Request(url + "/receipts", data=canonical_json_bytes(receipt))
            with urllib.request.urlopen(request, timeout=30) as response:
                from fl_forensics.witness_models import WitnessRegistration

                ack = WitnessRegistration.model_validate(json.load(response))
            verify_registration(
                ack,
                policy=store.policy,
                context=store.context,
                witness_public_key=store.witness_public_key,
                client_public_keys=store.client_public_keys,
                trust_store=store.trust_store,
            )
            write_json_once(root / f"{client_id}-ack.json", ack.model_dump(mode="json"))
        ready = {
            "status": "running_local_development_demo",
            "witness_url": url,
            "policy_url": url + "/policy",
            "snapshot_url_after_closure": url + "/snapshot",
            "deadline": store.context.core.expires_at,
            "registered_receipts": 2,
            "witness_pid": process.pid,
            "controller_pid": os.getpid(),
            "development_TSA_only": True,
            "independent_administration_validated": False,
            "workspace": str(root),
        }
        atomic_json(root / "process.json", {"pid": os.getpid(), "identity": identity(os.getpid())})
        atomic_json(root / "ready.json", ready)
        print(json.dumps(ready), flush=True)
        while not stopped.wait(1):
            if process.poll() is not None:
                raise ValueError("witness process exited")
        return {"status": "stopped", "persistent_state_preserved": True}
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        tsa.shutdown()
        tsa.server_close()
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--tsa-port", type=int, default=8766)
    parser.add_argument("--window-seconds", type=int, default=3600)
    parser.add_argument("--stop", action="store_true")
    arguments = parser.parse_args()
    if not 10 <= arguments.window_seconds <= 86400:
        parser.error("window must be between 10 seconds and one day")
    print(json.dumps(run(arguments)), flush=True)
