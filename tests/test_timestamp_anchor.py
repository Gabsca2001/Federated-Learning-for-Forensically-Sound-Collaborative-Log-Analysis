from __future__ import annotations

import json
from pathlib import Path

import pytest

from fl_forensics import timestamp_anchor
from fl_forensics.anchor_models import TimestampProof
from fl_forensics.canonical import canonical_json_bytes, digest_object, sha256_bytes
from fl_forensics.merkle_models import MerkleCore, MerkleTreeManifest
from fl_forensics.timestamp_anchor import (
    TimestampAnchorError,
    _anchor_subject,
    _message_imprint,
    create_timestamp_anchor,
    verify_timestamp_anchor,
)


def _tree() -> MerkleTreeManifest:
    core = MerkleCore(
        source_preservation_id="m8-preservation-test",
        source_preservation_manifest_sha256="a" * 64,
        source_preservation_core_sha256="b" * 64,
        source_inventory_sha256="c" * 64,
        artifact_leaf_count=1,
        external_evidence_leaf_count=0,
        leaf_count=1,
        level_count=1,
        leaves=[
            {
                "index": 0,
                "leaf_key": "artifact:a.json:artifact-a",
                "payload": {
                    "leaf_kind": "preserved-artifact",
                    "identity": "artifact-a",
                    "relative_path": "a.json",
                    "content_sha256": "d" * 64,
                    "size_bytes": 10,
                    "source_descriptor_sha256": "e" * 64,
                },
                "leaf_sha256": "f" * 64,
            }
        ],
        levels=[["f" * 64]],
        root_sha256="f" * 64,
    )
    core_digest = digest_object(core.model_dump(mode="json"))
    return MerkleTreeManifest(
        tree_id=f"m8-merkle-tree-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
    )


def test_anchor_subject_is_deterministic() -> None:
    first = _anchor_subject(_tree(), "1" * 64)
    second = _anchor_subject(_tree(), "1" * 64)
    assert first == second
    assert first.core.merkle_root_sha256 == "f" * 64
    assert first.requested_protocol == "RFC3161"


def test_anchor_subject_changes_with_merkle_tree_digest() -> None:
    first = _anchor_subject(_tree(), "1" * 64)
    second = _anchor_subject(_tree(), "2" * 64)
    assert first.anchor_id != second.anchor_id


def test_message_imprint_parses_openssl_output() -> None:
    details = """Message data:
    0000 - aa aa aa aa aa aa aa aa-aa aa aa aa aa aa aa aa   ................
    0010 - aa aa aa aa aa aa aa aa-aa aa aa aa aa aa aa aa   ................
"""
    assert _message_imprint(details) == "a" * 64


def test_message_imprint_rejects_non_sha256_value() -> None:
    with pytest.raises(TimestampAnchorError, match="not SHA-256"):
        _message_imprint(
            "Message data:\n    0000 - aa aa aa aa   ....\n"
        )


def _details(imprint: str) -> str:
    first = " ".join(imprint[index : index + 2] for index in range(0, 32, 2))
    second = " ".join(imprint[index : index + 2] for index in range(32, 64, 2))
    return f"""Status: Granted.
Policy OID: 2.16.840.1.114412.7.1
Hash Algorithm: sha256
Message data:
    0000 - {first}   ................
    0010 - {second}   ................
Serial number: 0x01
Time stamp: Aug 25 12:00:00 2026 GMT
Accuracy: unspecified
Ordering: no
Nonce: 0x01
TSA: DirName:/C=US/O=Example/CN=Example TSA
Extensions:
"""


def _published_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    tree = _tree()
    tree_path = tmp_path / "merkle-tree.json"
    tree_path.write_bytes(canonical_json_bytes(tree.model_dump(mode="json")) + b"\n")
    tree_sha256 = sha256_bytes(tree_path.read_bytes())
    trust_store = tmp_path / "ca-certificates.crt"
    trust_store.write_bytes(b"TEST TRUST STORE\n")
    monkeypatch.setattr(
        timestamp_anchor,
        "_settings",
        lambda _path: (
            tmp_path,
            {
                "merkle_workspace": "merkle",
                "merkle_config": "merkle.yaml",
                "tsa_url": "https://tsa.example.test",
                "trust_store": str(trust_store),
                "request_timeout_seconds": 30,
                "hash_algorithm": "sha256",
            },
            "1" * 64,
        ),
    )
    monkeypatch.setattr(
        timestamp_anchor,
        "_validated_merkle",
        lambda _root, _settings, verify_source: (
            tree,
            tree_path,
            tree_sha256,
        ),
    )
    monkeypatch.setattr(timestamp_anchor, "_openssl_query", lambda _data: b"QUERY")
    monkeypatch.setattr(
        timestamp_anchor,
        "_post_timestamp",
        lambda _url, _query, _timeout: b"RESPONSE",
    )
    monkeypatch.setattr(
        timestamp_anchor,
        "_extract_certificates",
        lambda _response: b"CERTIFICATES",
    )
    monkeypatch.setattr(
        timestamp_anchor,
        "_openssl_verify",
        lambda **_kwargs: "Verification: OK",
    )

    def details(response: bytes) -> str:
        assert response == b"RESPONSE"
        anchor = _anchor_subject(tree, tree_sha256)
        subject_bytes = canonical_json_bytes(anchor.model_dump(mode="json")) + b"\n"
        return _details(sha256_bytes(subject_bytes))

    monkeypatch.setattr(timestamp_anchor, "_timestamp_details", details)
    workspace = tmp_path / "published"
    create_timestamp_anchor(
        output=workspace,
        config_path=tmp_path / "timestamp.yaml",
        verify_source=False,
    )
    return workspace


def test_mocked_timestamp_publication_and_offline_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _published_fixture(tmp_path, monkeypatch)
    result = verify_timestamp_anchor(
        workspace=workspace,
        config_path=tmp_path / "timestamp.yaml",
        verify_source=False,
    )
    assert result["status"] == "verified"
    assert result["offline_signature_verified"] is True
    assert sorted(path.name for path in workspace.iterdir()) == (
        timestamp_anchor.EXPECTED_FILES
    )


def test_verifier_rejects_tampered_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _published_fixture(tmp_path, monkeypatch)
    path = workspace / "timestamp-proof.json"
    value = json.loads(path.read_text())
    value["serial_number"] = "0x02"
    path.chmod(0o640)
    path.write_bytes(canonical_json_bytes(value) + b"\n")
    result = verify_timestamp_anchor(
        workspace=workspace,
        config_path=tmp_path / "timestamp.yaml",
        verify_source=False,
    )
    assert result["status"] == "failed"
    assert "proof differs" in result["errors"][0]


def test_verifier_rejects_tampered_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _published_fixture(tmp_path, monkeypatch)

    def reject_response(**_kwargs) -> str:
        raise TimestampAnchorError("timestamp signature verification failed")

    monkeypatch.setattr(timestamp_anchor, "_openssl_verify", reject_response)
    result = verify_timestamp_anchor(
        workspace=workspace,
        config_path=tmp_path / "timestamp.yaml",
        verify_source=False,
    )
    assert result["status"] == "failed"
    assert result["errors"] == ["timestamp signature verification failed"]


def test_verifier_rejects_unexpected_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _published_fixture(tmp_path, monkeypatch)
    (workspace / "unexpected.json").write_text("{}\n")
    result = verify_timestamp_anchor(
        workspace=workspace,
        config_path=tmp_path / "timestamp.yaml",
        verify_source=False,
    )
    assert result["status"] == "failed"
    assert result["errors"] == ["unexpected M8.3 workspace artifact set"]


def test_timestamp_proof_schema_rejects_unverified_status() -> None:
    value = {
        "schema_version": "1.0",
        "artifact_type": "m8_rfc3161_timestamp_proof",
        "proof_id": "proof",
        "anchor_id": "anchor",
        "tsa_url": "https://tsa.example.test",
        "protocol": "RFC3161",
        "hash_algorithm": "sha256",
        "message_imprint_sha256": "0" * 64,
        "anchor_subject_sha256": "0" * 64,
        "timestamp_request_sha256": "0" * 64,
        "timestamp_response_sha256": "0" * 64,
        "tsa_certificates_sha256": "0" * 64,
        "trust_store_sha256": "0" * 64,
        "policy_oid": "1.2.3",
        "serial_number": "1",
        "gen_time": "now",
        "tsa_name": "tsa",
        "nonce_present": True,
        "openssl_verification": "failed",
    }
    with pytest.raises(ValueError):
        TimestampProof.model_validate(value)
