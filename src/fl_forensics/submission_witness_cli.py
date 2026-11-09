"""Independent witness service and CLI; remote deployments require TLS.

No API accepts a caller-supplied registration time or a caller-selected TSA.
Only the operator's local CLI can close a context. Request authentication is
the enrolled client signature; coordinator keys cannot manufacture receipts.
"""

from __future__ import annotations

import json
import os
import sqlite3
import ssl
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes, sha256_file
from .crypto import SoftwareECDSASigner, load_public_key
from .secure_round_models import SecureRoundContext
from .storage import load_json, write_json_once, write_once
from .submission_evidence_models import RoundInputInventory, SubmissionReceipt
from .submission_witness import (
    WitnessError,
    WitnessStore,
    create_witness_policy,
    verify_policy,
    verify_registration,
    verify_witness_inventory,
    verify_witness_snapshot,
)
from .witness_models import WitnessPolicy, WitnessRegistration, WitnessSnapshot
from .witness_time import RFC3161Provider


def _keys(path: Path) -> dict[str, Any]:
    data = load_json(path)
    data = {
        name: value["public_key"] if isinstance(value, dict) else value
        for name, value in data.items()
    }
    return {
        name: load_public_key(
            (Path(value) if Path(value).is_absolute() else path.parent / value).read_bytes()
        )
        for name, value in data.items()
    }


def _key_levels(path: Path) -> dict[str, str]:
    return {
        name: value["trust_level"] if isinstance(value, dict) else "software-development"
        for name, value in load_json(path).items()
    }


def export_enrollment_bindings(
    *,
    context_path: Path,
    trust_workspace: Path,
    authority_public_key_path: Path,
    coordinator_public_key_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Export ESK keys/levels using an externally pinned enrollment authority.

    This checks enrollment at context issuance; it is not a fresh Quote or
    continuous revocation/admission appraisal.
    """
    from .crypto import public_key_id
    from .secure_round import _enrollment, _revoked
    from .submission_evidence import _context_valid, _time

    context = SecureRoundContext.model_validate(load_json(context_path))
    coordinator_key = load_public_key(coordinator_public_key_path.read_bytes())
    authority_key = load_public_key(authority_public_key_path.read_bytes())
    if not _context_valid(context, coordinator_key):
        raise WitnessError("invalid authenticated round context")
    issued, expires = _time(context.core.issued_at), _time(context.core.expires_at)
    bindings, records, public_keys = {}, {}, {}
    for index, contract in enumerate(context.core.clients):
        record = _enrollment(trust_workspace, contract.client_id, authority_key)
        core = record.core
        public_key = load_public_key(core.esk_public_key_pem.encode())
        if (
            core.client_id != contract.client_id
            or core.enrollment_id != contract.enrollment_id
            or core.node_id != contract.node_id
            or core.esk_key_id != public_key_id(public_key)
            or core.status != "active"
            or not _time(core.valid_from) <= issued < expires <= _time(core.valid_until)
            or _revoked(trust_workspace, record, authority_key, at=issued)
        ):
            raise WitnessError("enrollment differs from authenticated context or validity interval")
        name = f"client-{index}.pem"
        public_keys[name] = core.esk_public_key_pem.encode()
        bindings[core.client_id] = {"public_key": name, "trust_level": core.trust_level}
        records[core.client_id] = record.core_digest
    for name, data in public_keys.items():
        write_once(output.parent / name, data)
    write_json_once(output, bindings)
    return {
        "status": "exported_verified_enrollment_bindings",
        "context_digest": context.core_digest,
        "authority_key_id": public_key_id(authority_key),
        "enrollment_core_digests": records,
        "bindings_sha256": sha256_file(output),
        "runtime_attestation_verified": False,
    }


def initialize_state(
    *,
    state: Path,
    context_path: Path,
    coordinator_public_key_path: Path,
    client_keys_path: Path,
    tsa_trust_store_path: Path,
    tsa_url: str,
    tsa_policy_oid: str,
    maximum_accuracy_microseconds: int = 1_000_000,
    registration_deadline: str | None = None,
) -> dict[str, Any]:
    if not tsa_url.startswith(("https://", "http://127.0.0.1:", "http://localhost:")):
        raise WitnessError("TSA URL must use HTTPS, or loopback HTTP for development")
    if state.exists() and any(state.iterdir()):
        raise WitnessError("witness initialization requires a new empty state directory")
    context = SecureRoundContext.model_validate(load_json(context_path))
    coordinator_key = load_public_key(coordinator_public_key_path.read_bytes())
    client_keys = _keys(client_keys_path)
    trust_store = tsa_trust_store_path.read_bytes()
    signer = SoftwareECDSASigner.generate()
    policy = create_witness_policy(
        context=context,
        coordinator_public_key=coordinator_key,
        client_public_keys=client_keys,
        signer=signer,
        trust_store=trust_store,
        tsa_policy_oid=tsa_policy_oid,
        maximum_accuracy_microseconds=maximum_accuracy_microseconds,
        client_signing_trust_levels=_key_levels(client_keys_path),
        registration_deadline=registration_deadline,
    )
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(state / "witness-private.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(signer.private_pem())
    write_once(state / "witness-public.pem", signer.public_pem())
    write_once(state / "coordinator-public.pem", coordinator_public_key_path.read_bytes())
    write_once(state / "tsa-trust-store.pem", trust_store)
    write_json_once(state / "context.json", context.model_dump(mode="json"))
    write_json_once(state / "policy.json", policy.model_dump(mode="json"))
    locations = {}
    for index, (client_id, public_key) in enumerate(sorted(client_keys.items())):
        from cryptography.hazmat.primitives import serialization

        filename = f"client-keys/{index}.pem"
        write_once(
            state / filename,
            public_key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
        )
        locations[client_id] = {
            "public_key": filename,
            "trust_level": policy.core.client_signing_trust_levels[client_id],
        }
    write_json_once(state / "client-keys.json", locations)
    write_json_once(
        state / "settings.json",
        {
            "tsa_url": tsa_url,
            "expected_policy_digest": policy.core_digest,
        },
    )
    return {
        "status": "initialized",
        "policy_digest": policy.core_digest,
        "witness_key_id": signer.key_id,
        "deployment_independence_verified": False,
        "instruction": "Distribute the public key and policy digest outside coordinator control.",
    }


def open_store(state: Path) -> WitnessStore:
    settings = load_json(state / "settings.json")
    return WitnessStore(
        database=state / "registrations.sqlite3",
        policy=WitnessPolicy.model_validate(load_json(state / "policy.json")),
        context=SecureRoundContext.model_validate(load_json(state / "context.json")),
        expected_policy_digest=settings["expected_policy_digest"],
        signer=SoftwareECDSASigner.load(state / "witness-private.pem"),
        witness_public_key=load_public_key((state / "witness-public.pem").read_bytes()),
        coordinator_public_key=load_public_key((state / "coordinator-public.pem").read_bytes()),
        client_public_keys=_keys(state / "client-keys.json"),
        trust_store=(state / "tsa-trust-store.pem").read_bytes(),
        timestamp_provider=RFC3161Provider(settings["tsa_url"]),
    )


def make_server(store: WitnessStore, host: str = "127.0.0.1", port: int = 0):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, format, *args):
            pass  # Receipt identifiers must not leak into default HTTP access logs.

        def respond(self, value, code=200):
            data = canonical_json_bytes(value)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            try:
                if self.path == "/policy":
                    self.respond(store.policy.model_dump(mode="json"))
                elif self.path == "/snapshot":
                    self.respond(store.snapshot().model_dump(mode="json"))
                else:
                    self.respond({"error": "unknown endpoint"}, 404)
            except ValueError as exc:
                self.respond({"error": str(exc)}, 409)

        def do_POST(self):
            if self.path != "/receipts":
                self.respond({"error": "unknown endpoint"}, 404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1_048_576:
                    self.respond({"error": "receipt body limit exceeded or missing length"}, 413)
                    return
                receipt = SubmissionReceipt.model_validate_json(self.rfile.read(length))
                entry = store.register(receipt)
                self.respond(entry.model_dump(mode="json"))
            except (ValueError, OSError, sqlite3.Error) as exc:
                self.respond({"error": str(exc)}, 409)

    return ThreadingHTTPServer((host, port), Handler)


def add_witness_commands(subparsers: Any) -> None:
    from .witness_round import add_round_commands

    add_round_commands(subparsers)
    export = subparsers.add_parser(
        "witness-enrollment-keys", help="export pinned enrolled ESK keys and signing levels"
    )
    export.add_argument("--context", type=Path, required=True)
    export.add_argument("--trust-workspace", type=Path, required=True)
    export.add_argument("--authority-public-key", type=Path, required=True)
    export.add_argument("--coordinator-public-key", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    init = subparsers.add_parser("witness-init", help="initialize a separate receipt witness")
    init.add_argument("--state", type=Path, required=True)
    init.add_argument("--context", type=Path, required=True)
    init.add_argument("--coordinator-public-key", type=Path, required=True)
    init.add_argument("--client-keys", type=Path, required=True)
    init.add_argument("--tsa-trust-store", type=Path, required=True)
    init.add_argument("--tsa-url", required=True)
    init.add_argument("--tsa-policy-oid", required=True)
    init.add_argument("--maximum-accuracy-microseconds", type=int, default=1_000_000)
    init.add_argument(
        "--registration-deadline",
        help="UTC cutoff strictly before context expiry; opts into policy v2",
    )
    serve = subparsers.add_parser("witness-serve", help="serve signed receipt registration")
    serve.add_argument("--state", type=Path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--tls-cert", type=Path)
    serve.add_argument("--tls-private-key", type=Path)
    close = subparsers.add_parser("witness-close", help="seal the full log after the deadline")
    close.add_argument("--state", type=Path, required=True)
    close.add_argument("--output", type=Path, required=True)
    fetch = subparsers.add_parser(
        "witness-fetch", help="retrieve a closure for separate verification"
    )
    fetch.add_argument("--url", required=True)
    fetch.add_argument("--output", type=Path, required=True)
    for name in ("witness-submit", "witness-verify"):
        command = subparsers.add_parser(
            name, help="verify against external authority and policy pins"
        )
        command.add_argument("--expected-policy-digest", required=True)
        command.add_argument("--witness-public-key", type=Path, required=True)
        command.add_argument("--coordinator-public-key", type=Path, required=True)
        command.add_argument("--client-keys", type=Path, required=True)
        command.add_argument("--tsa-trust-store", type=Path, required=True)
        if name == "witness-submit":
            command.add_argument("--url", required=True)
            command.add_argument("--receipt", type=Path, required=True)
            command.add_argument("--output", type=Path, required=True)
            command.add_argument("--policy", type=Path, required=True)
            command.add_argument("--context", type=Path, required=True)
        else:
            command.add_argument("--snapshot", type=Path, required=True)
            command.add_argument("--expected-closure-digest", required=True)
            command.add_argument("--acknowledgement", type=Path, action="append", default=[])
            command.add_argument("--inventory", type=Path)
            command.add_argument("--submissions-root", type=Path)


def _request(url: str, value: dict[str, Any] | None = None) -> dict[str, Any]:
    if not url.startswith(("https://", "http://127.0.0.1:", "http://localhost:")):
        raise WitnessError("remote witness requires HTTPS")
    request = urllib.request.Request(
        url,
        data=canonical_json_bytes(value) if value is not None else None,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(16_777_217)
        if len(data) > 16_777_216:
            raise WitnessError("witness response exceeds size limit")
        return json.loads(data)


def run_witness_command(arguments: Any) -> tuple[dict[str, Any], int]:
    try:
        name = arguments.command
        if name.startswith("witness-round-"):
            from .witness_round import run_round_command

            return run_round_command(arguments)
        if name == "witness-enrollment-keys":
            return export_enrollment_bindings(
                context_path=arguments.context,
                trust_workspace=arguments.trust_workspace,
                authority_public_key_path=arguments.authority_public_key,
                coordinator_public_key_path=arguments.coordinator_public_key,
                output=arguments.output,
            ), 0
        if name == "witness-init":
            result = initialize_state(
                state=arguments.state,
                context_path=arguments.context,
                coordinator_public_key_path=arguments.coordinator_public_key,
                client_keys_path=arguments.client_keys,
                tsa_trust_store_path=arguments.tsa_trust_store,
                tsa_url=arguments.tsa_url,
                tsa_policy_oid=arguments.tsa_policy_oid,
                maximum_accuracy_microseconds=arguments.maximum_accuracy_microseconds,
                registration_deadline=arguments.registration_deadline,
            )
            return result, 0
        if name == "witness-serve":
            if bool(arguments.tls_cert) != bool(arguments.tls_private_key):
                raise WitnessError("TLS certificate and key must be supplied together")
            if arguments.host not in {"127.0.0.1", "localhost", "::1"} and not arguments.tls_cert:
                raise WitnessError("non-loopback witness listeners require TLS")
            server = make_server(open_store(arguments.state), arguments.host, arguments.port)
            if arguments.tls_cert:
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.minimum_version = ssl.TLSVersion.TLSv1_2
                tls.load_cert_chain(arguments.tls_cert, arguments.tls_private_key)
                server.socket = tls.wrap_socket(server.socket, server_side=True)
            print(json.dumps({"status": "listening", "address": server.server_address}), flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return {"status": "stopped"}, 0
        if name == "witness-close":
            snapshot = open_store(arguments.state).close()
            write_json_once(arguments.output, snapshot.model_dump(mode="json"))
            return {
                "status": "closed",
                "closure_digest": snapshot.closure.core_digest,
                "instruction": "Retain this closure digest outside the coordinator.",
            }, 0
        if name == "witness-fetch":
            snapshot = WitnessSnapshot.model_validate(
                _request(arguments.url.rstrip("/") + "/snapshot")
            )
            write_json_once(arguments.output, snapshot.model_dump(mode="json"))
            return {
                "status": "retrieved_not_verified",
                "closure_digest": snapshot.closure.core_digest,
            }, 0
        common = {
            "expected_policy_digest": arguments.expected_policy_digest,
            "witness_public_key": load_public_key(arguments.witness_public_key.read_bytes()),
            "coordinator_public_key": load_public_key(
                arguments.coordinator_public_key.read_bytes()
            ),
            "client_public_keys": _keys(arguments.client_keys),
            "trust_store": arguments.tsa_trust_store.read_bytes(),
        }
        if name == "witness-submit":
            policy = WitnessPolicy.model_validate(load_json(arguments.policy))
            context = SecureRoundContext.model_validate(load_json(arguments.context))
            verify_policy(policy=policy, context=context, **common)
            receipt = SubmissionReceipt.model_validate(load_json(arguments.receipt))
            ack = WitnessRegistration.model_validate(
                _request(arguments.url.rstrip("/") + "/receipts", receipt.model_dump(mode="json"))
            )
            verify_registration(
                ack,
                policy=policy,
                context=context,
                **{
                    k: common[k]
                    for k in ("witness_public_key", "client_public_keys", "trust_store")
                },
            )
            if ack.receipt.core_digest != receipt.core_digest:
                raise WitnessError("witness acknowledged a different receipt")
            write_json_once(arguments.output, ack.model_dump(mode="json"))
            return {
                "status": "registered",
                "sequence": ack.core.subject.sequence,
                "eligibility": ack.core.eligibility,
                "acknowledgement_digest": ack.core_digest,
            }, 0
        snapshot = WitnessSnapshot.model_validate(load_json(arguments.snapshot))
        common.update(
            snapshot=snapshot,
            expected_closure_digest=arguments.expected_closure_digest,
            retained_acknowledgements=[
                WitnessRegistration.model_validate(load_json(path))
                for path in arguments.acknowledgement
            ],
        )
        if arguments.inventory:
            if not arguments.submissions_root:
                raise WitnessError("inventory reconstruction requires --submissions-root")
            paths = {}
            for entry in snapshot.registrations:
                # Client identifiers are identifiers, never path components.
                client_id = entry.receipt.core.client_id
                if Path(client_id).name != client_id or client_id in {".", ".."}:
                    raise WitnessError("unsafe client identifier for directory adapter")
                path = arguments.submissions_root / client_id / "bundle.json"
                if path.is_file():
                    paths.setdefault(sha256_file(path), path)
                    paths.setdefault(entry.receipt.core.bundle_sha256, path)
            result = verify_witness_inventory(
                inventory=RoundInputInventory.model_validate(load_json(arguments.inventory)),
                bundle_paths=paths,
                **common,
            )
        else:
            result = verify_witness_snapshot(**common)
        return result, int(
            result["status"] not in {"verified_registration_set", "verified_eligible_intake"}
        )
    except (ValueError, TypeError, KeyError, OSError, sqlite3.Error) as exc:
        return {"status": "invalid", "errors": [str(exc)]}, 1
