"""M8.3 RFC 3161 timestamp acquisition and offline verification."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from .anchor_models import (
    TIMESTAMP_STATE,
    AnchorSubject,
    AnchorSubjectCore,
    TimestampManifest,
    TimestampManifestCore,
    TimestampProof,
)
from .canonical import canonical_json_bytes, digest_object, sha256_bytes, sha256_file
from .config import load_yaml
from .merkle import verify_merkle_tree
from .merkle_models import MerkleTreeManifest
from .storage import load_json, write_json_once, write_once

EXPECTED_FILES = [
    "anchor-subject.json",
    "manifest.json",
    "timestamp-proof.json",
    "timestamp-request.tsq",
    "timestamp-response.tsr",
    "trust-store.pem",
    "tsa-certificates.pem",
]


class TimestampAnchorError(ValueError):
    """Raised when trusted-time acquisition or verification fails."""


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _settings(config_path: Path) -> tuple[Path, dict[str, Any], str]:
    value, digest = load_yaml(config_path)
    settings = value.get("timestamp")
    if not isinstance(settings, dict):
        raise TimestampAnchorError("missing timestamp configuration")
    if settings.get("hash_algorithm") != "sha256":
        raise TimestampAnchorError("M8.3 requires SHA-256 timestamp imprints")
    timeout = settings.get("request_timeout_seconds")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0:
        raise TimestampAnchorError("invalid timestamp request timeout")
    url = settings.get("tsa_url")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise TimestampAnchorError("invalid RFC 3161 TSA URL")
    return config_path.resolve().parent.parent, settings, digest


def _run(command: list[str], *, input_bytes: bytes | None = None) -> bytes:
    if shutil.which(command[0]) is None:
        raise TimestampAnchorError(f"required command is unavailable: {command[0]}")
    result = subprocess.run(
        command,
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        if not detail:
            detail = result.stdout.decode("utf-8", errors="replace").strip()
        raise TimestampAnchorError(f"{' '.join(command)} failed: {detail}")
    return result.stdout


def _validated_merkle(
    root: Path, settings: dict[str, Any], *, verify_source: bool
) -> tuple[MerkleTreeManifest, Path, str]:
    workspace = _resolve(root, str(settings["merkle_workspace"]))
    config_path = _resolve(root, str(settings["merkle_config"]))
    if verify_source:
        result = verify_merkle_tree(workspace=workspace, config_path=config_path)
        if result.get("status") != "verified":
            raise TimestampAnchorError(
                f"source M8.2 verification failed: {result.get('errors', [])}"
            )
    path = workspace / "merkle-tree.json"
    tree = MerkleTreeManifest.model_validate(load_json(path))
    expected_core = digest_object(tree.core.model_dump(mode="json"))
    if tree.canonical_core_sha256 != expected_core:
        raise TimestampAnchorError("source Merkle core digest mismatch")
    if tree.tree_id != f"m8-merkle-tree-{expected_core[:24]}":
        raise TimestampAnchorError("source Merkle identity mismatch")
    return tree, path, sha256_file(path)


def _anchor_subject(tree: MerkleTreeManifest, tree_sha256: str) -> AnchorSubject:
    core = AnchorSubjectCore(
        merkle_tree_id=tree.tree_id,
        merkle_root_sha256=tree.core.root_sha256,
        merkle_tree_sha256=tree_sha256,
        merkle_core_sha256=tree.canonical_core_sha256,
        merkle_leaf_count=tree.core.leaf_count,
        source_preservation_id=tree.core.source_preservation_id,
        source_preservation_manifest_sha256=(
            tree.core.source_preservation_manifest_sha256
        ),
        commitment_algorithm=tree.core.algorithm,
    )
    core_digest = digest_object(core.model_dump(mode="json"))
    return AnchorSubject(
        anchor_id=f"m8-anchor-subject-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
    )


def _openssl_query(subject_bytes: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as temporary:
        subject_path = Path(temporary) / "anchor-subject.json"
        subject_path.write_bytes(subject_bytes)
        return _run(
            [
                "openssl",
                "ts",
                "-query",
                "-data",
                str(subject_path),
                "-sha256",
                "-cert",
            ]
        )


def _post_timestamp(url: str, request_bytes: bytes, timeout: int) -> bytes:
    request = urllib.request.Request(
        url,
        data=request_bytes,
        method="POST",
        headers={
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
            "User-Agent": "fl-forensics-m8-rfc3161/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = response.read()
            content_type = response.headers.get_content_type()
    except OSError as exc:
        raise TimestampAnchorError(f"RFC 3161 request failed: {exc}") from exc
    if content_type not in {
        "application/timestamp-reply",
        "application/octet-stream",
    }:
        raise TimestampAnchorError(
            f"unexpected RFC 3161 response content type: {content_type}"
        )
    if not value:
        raise TimestampAnchorError("RFC 3161 response is empty")
    return value


def _extract_certificates(response_bytes: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        response_path = root / "response.tsr"
        token_path = root / "token.p7"
        response_path.write_bytes(response_bytes)
        _run(
            [
                "openssl",
                "ts",
                "-reply",
                "-in",
                str(response_path),
                "-token_out",
                "-out",
                str(token_path),
            ]
        )
        certificates = _run(
            [
                "openssl",
                "pkcs7",
                "-inform",
                "DER",
                "-in",
                str(token_path),
                "-print_certs",
            ]
        )
    if b"BEGIN CERTIFICATE" not in certificates:
        raise TimestampAnchorError("timestamp response contains no TSA certificate")
    return certificates


def _openssl_verify(
    *, request_bytes: bytes, response_bytes: bytes, certificates: bytes, trust_store: bytes
) -> str:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        paths = {
            "request": root / "request.tsq",
            "response": root / "response.tsr",
            "certificates": root / "tsa-certificates.pem",
            "trust": root / "trust-store.pem",
        }
        paths["request"].write_bytes(request_bytes)
        paths["response"].write_bytes(response_bytes)
        paths["certificates"].write_bytes(certificates)
        paths["trust"].write_bytes(trust_store)
        output = _run(
            [
                "openssl",
                "ts",
                "-verify",
                "-queryfile",
                str(paths["request"]),
                "-in",
                str(paths["response"]),
                "-CAfile",
                str(paths["trust"]),
                "-untrusted",
                str(paths["certificates"]),
            ]
        )
    result = output.decode("utf-8", errors="strict").strip()
    if result != "Verification: OK":
        raise TimestampAnchorError(f"unexpected OpenSSL timestamp result: {result}")
    return result


def _timestamp_details(response_bytes: bytes) -> str:
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "response.tsr"
        path.write_bytes(response_bytes)
        output = _run(
            ["openssl", "ts", "-reply", "-in", str(path), "-text"]
        )
    return output.decode("utf-8", errors="strict")


def _field(details: str, label: str) -> str:
    match = re.search(rf"^{re.escape(label)}:\s*(.+)$", details, re.MULTILINE)
    if match is None:
        raise TimestampAnchorError(f"timestamp response is missing {label}")
    return match.group(1).strip()


def _message_imprint(details: str) -> str:
    match = re.search(
        r"Message data:\s*\n((?:\s+[0-9a-f]{4}\s+-\s+[0-9a-f -]+\s+.+\n?)+)",
        details,
        re.IGNORECASE,
    )
    if match is None:
        raise TimestampAnchorError("timestamp response is missing message imprint")
    groups = re.findall(r"[0-9a-f]{4}\s+-\s+([0-9a-f -]+)", match.group(1), re.IGNORECASE)
    value = "".join(groups).replace(" ", "").replace("-", "").lower()
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise TimestampAnchorError("timestamp message imprint is not SHA-256")
    return value


def _proof(
    *,
    anchor: AnchorSubject,
    subject_bytes: bytes,
    request_bytes: bytes,
    response_bytes: bytes,
    certificates: bytes,
    trust_store: bytes,
    tsa_url: str,
) -> TimestampProof:
    verification = _openssl_verify(
        request_bytes=request_bytes,
        response_bytes=response_bytes,
        certificates=certificates,
        trust_store=trust_store,
    )
    details = _timestamp_details(response_bytes)
    if _field(details, "Status") not in {"Granted.", "Granted with mods."}:
        raise TimestampAnchorError("timestamp response status is not granted")
    if _field(details, "Hash Algorithm").lower() != "sha256":
        raise TimestampAnchorError("timestamp response does not use SHA-256")
    if "Nonce:" not in details:
        raise TimestampAnchorError("timestamp response does not contain the request nonce")
    subject_sha256 = sha256_bytes(subject_bytes)
    imprint = _message_imprint(details)
    if imprint != subject_sha256:
        raise TimestampAnchorError("timestamp message imprint differs from anchor subject")
    response_sha256 = sha256_bytes(response_bytes)
    return TimestampProof(
        proof_id=f"rfc3161-proof-{response_sha256[:24]}",
        anchor_id=anchor.anchor_id,
        tsa_url=tsa_url,
        message_imprint_sha256=imprint,
        anchor_subject_sha256=subject_sha256,
        timestamp_request_sha256=sha256_bytes(request_bytes),
        timestamp_response_sha256=response_sha256,
        tsa_certificates_sha256=sha256_bytes(certificates),
        trust_store_sha256=sha256_bytes(trust_store),
        policy_oid=_field(details, "Policy OID"),
        serial_number=_field(details, "Serial number"),
        gen_time=_field(details, "Time stamp"),
        tsa_name=_field(details, "TSA"),
        nonce_present=True,
        openssl_verification=verification,
    )


def _manifest(
    *,
    anchor: AnchorSubject,
    subject_bytes: bytes,
    proof: TimestampProof,
    proof_bytes: bytes,
    tree: MerkleTreeManifest,
    config_sha256: str,
) -> TimestampManifest:
    core = TimestampManifestCore(
        anchor_id=anchor.anchor_id,
        anchor_subject_sha256=sha256_bytes(subject_bytes),
        proof_id=proof.proof_id,
        timestamp_proof_sha256=sha256_bytes(proof_bytes),
        timestamp_request_sha256=proof.timestamp_request_sha256,
        timestamp_response_sha256=proof.timestamp_response_sha256,
        tsa_certificates_sha256=proof.tsa_certificates_sha256,
        trust_store_sha256=proof.trust_store_sha256,
        merkle_tree_id=tree.tree_id,
        merkle_root_sha256=tree.core.root_sha256,
        tsa_url=proof.tsa_url,
        assurance_state=TIMESTAMP_STATE,
    )
    core_digest = digest_object(core.model_dump(mode="json"))
    return TimestampManifest(
        timestamp_id=f"m8-timestamp-anchor-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
        implementation_sha256=sha256_file(Path(__file__)),
        config_sha256=config_sha256,
    )


def create_timestamp_anchor(
    *, output: Path, config_path: Path, verify_source: bool = True
) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"timestamp workspace is not empty: {output}")
    root, settings, config_sha256 = _settings(config_path)
    tree, _tree_path, tree_sha256 = _validated_merkle(
        root, settings, verify_source=verify_source
    )
    anchor = _anchor_subject(tree, tree_sha256)
    subject_bytes = canonical_json_bytes(anchor.model_dump(mode="json")) + b"\n"
    request_bytes = _openssl_query(subject_bytes)
    response_bytes = _post_timestamp(
        str(settings["tsa_url"]),
        request_bytes,
        int(settings["request_timeout_seconds"]),
    )
    certificates = _extract_certificates(response_bytes)
    trust_store_path = _resolve(root, str(settings["trust_store"]))
    if not trust_store_path.is_file():
        raise TimestampAnchorError(f"timestamp trust store is missing: {trust_store_path}")
    trust_store = trust_store_path.read_bytes()
    proof = _proof(
        anchor=anchor,
        subject_bytes=subject_bytes,
        request_bytes=request_bytes,
        response_bytes=response_bytes,
        certificates=certificates,
        trust_store=trust_store,
        tsa_url=str(settings["tsa_url"]),
    )
    proof_bytes = canonical_json_bytes(proof.model_dump(mode="json")) + b"\n"
    manifest = _manifest(
        anchor=anchor,
        subject_bytes=subject_bytes,
        proof=proof,
        proof_bytes=proof_bytes,
        tree=tree,
        config_sha256=config_sha256,
    )
    write_once(output / "anchor-subject.json", subject_bytes)
    write_once(output / "timestamp-request.tsq", request_bytes)
    write_once(output / "timestamp-response.tsr", response_bytes)
    write_once(output / "tsa-certificates.pem", certificates)
    write_once(output / "trust-store.pem", trust_store)
    write_once(output / "timestamp-proof.json", proof_bytes)
    write_json_once(output / "manifest.json", manifest.model_dump(mode="json"))
    return {
        "status": "time_anchored",
        "timestamp_id": manifest.timestamp_id,
        "anchor_id": anchor.anchor_id,
        "tree_id": tree.tree_id,
        "root_sha256": tree.core.root_sha256,
        "gen_time": proof.gen_time,
        "policy_oid": proof.policy_oid,
        "serial_number": proof.serial_number,
        "tsa_url": proof.tsa_url,
        "workspace": str(output),
    }


def verify_timestamp_anchor(
    *, workspace: Path, config_path: Path, verify_source: bool = True
) -> dict[str, Any]:
    errors: list[str] = []
    manifest: TimestampManifest | None = None
    proof: TimestampProof | None = None
    try:
        names = sorted(
            path.relative_to(workspace).as_posix()
            for path in workspace.rglob("*")
            if path.is_file()
        )
        if names != EXPECTED_FILES:
            raise TimestampAnchorError("unexpected M8.3 workspace artifact set")
        root, settings, config_sha256 = _settings(config_path)
        tree, _tree_path, tree_sha256 = _validated_merkle(
            root, settings, verify_source=verify_source
        )
        anchor = _anchor_subject(tree, tree_sha256)
        subject_bytes = canonical_json_bytes(anchor.model_dump(mode="json")) + b"\n"
        if (workspace / "anchor-subject.json").read_bytes() != subject_bytes:
            errors.append("anchor subject differs from reconstructed Merkle binding")
        request_bytes = (workspace / "timestamp-request.tsq").read_bytes()
        response_bytes = (workspace / "timestamp-response.tsr").read_bytes()
        certificates = (workspace / "tsa-certificates.pem").read_bytes()
        trust_store = (workspace / "trust-store.pem").read_bytes()
        expected_proof = _proof(
            anchor=anchor,
            subject_bytes=subject_bytes,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            certificates=certificates,
            trust_store=trust_store,
            tsa_url=str(settings["tsa_url"]),
        )
        proof_path = workspace / "timestamp-proof.json"
        proof = TimestampProof.model_validate(load_json(proof_path))
        proof_bytes = canonical_json_bytes(expected_proof.model_dump(mode="json")) + b"\n"
        if proof_path.read_bytes() != proof_bytes:
            errors.append("timestamp proof differs from cryptographic verification")
        expected_manifest = _manifest(
            anchor=anchor,
            subject_bytes=subject_bytes,
            proof=expected_proof,
            proof_bytes=proof_bytes,
            tree=tree,
            config_sha256=config_sha256,
        )
        manifest_path = workspace / "manifest.json"
        manifest = TimestampManifest.model_validate(load_json(manifest_path))
        expected_manifest_bytes = (
            canonical_json_bytes(expected_manifest.model_dump(mode="json")) + b"\n"
        )
        if manifest_path.read_bytes() != expected_manifest_bytes:
            errors.append("timestamp manifest differs from reconstruction")
    except (
        FileNotFoundError,
        KeyError,
        OSError,
        TimestampAnchorError,
        TypeError,
        ValueError,
    ) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "timestamp_id": manifest.timestamp_id if manifest else None,
        "anchor_id": manifest.core.anchor_id if manifest else None,
        "root_sha256": manifest.core.merkle_root_sha256 if manifest else None,
        "gen_time": proof.gen_time if proof else None,
        "source_recomputed": not errors,
        "offline_signature_verified": not errors,
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }
