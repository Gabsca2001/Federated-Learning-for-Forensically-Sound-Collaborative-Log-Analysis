"""Real OpenSSL RFC 3161 signature, trust, imprint and accuracy checks.

The test CA is local and disposable. This validates protocol implementation,
not an independently administered TSA or the accuracy of a production clock.
"""

from __future__ import annotations

import base64
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fl_forensics.canonical import sha256_bytes
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.timestamp_anchor import _openssl_query
from fl_forensics.witness_models import TimestampEvidence, WitnessPolicy, WitnessPolicyCore
from fl_forensics.witness_time import _accuracy, verify_timestamp

OID = "1.3.6.1.4.1.55555.1"


def make_local_tsa(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local witness test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    tsa_key = ec.generate_private_key(ec.SECP256R1())
    tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local witness test TSA")])
    tsa = (
        x509.CertificateBuilder()
        .subject_name(tsa_name)
        .issuer_name(ca_name)
        .public_key(tsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    (root / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (root / "tsa.pem").write_bytes(tsa.public_bytes(serialization.Encoding.PEM))
    (root / "tsa-private.pem").write_bytes(
        tsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (root / "tsa-private.pem").chmod(0o600)
    (root / "serial").write_text("01\n")
    config = root / "openssl.cnf"
    config.write_text(f"""[tsa]
default_tsa = local_tsa
[local_tsa]
serial = {root / "serial"}
crypto_device = builtin
signer_cert = {root / "tsa.pem"}
certs = {root / "ca.pem"}
signer_key = {root / "tsa-private.pem"}
signer_digest = sha256
default_policy = {OID}
digests = sha256
accuracy = secs:1
clock_precision_digits = 6
ordering = yes
tsa_name = yes
ess_cert_id_chain = yes
ess_cert_id_alg = sha256
""")
    return {"root": root, "config": config, "trust_store": (root / "ca.pem").read_bytes()}


def reply(authority: dict, query: bytes) -> bytes:
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "request.tsq"
        path.write_bytes(query)
        result = subprocess.run(
            [
                "openssl",
                "ts",
                "-reply",
                "-config",
                str(authority["config"]),
                "-queryfile",
                str(path),
            ],
            capture_output=True,
            check=True,
        )
        return result.stdout


@pytest.fixture
def real_timestamp(tmp_path):
    authority = make_local_tsa(tmp_path)
    subject = b"a committed witness registration, not a client timestamp"
    request = _openssl_query(subject)
    response = reply(authority, request)
    signer = SoftwareECDSASigner.generate()
    core = WitnessPolicyCore(
        witness_key_id=signer.key_id,
        context_digest="0" * 64,
        coordinator_key_id="coordinator",
        client_key_ids={},
        client_signing_trust_levels={},
        tsa_trust_store_sha256=sha256_bytes(authority["trust_store"]),
        tsa_policy_oid=OID,
        maximum_accuracy_microseconds=1_000_000,
    )
    from fl_forensics.submission_witness import _signed

    policy = WitnessPolicy(**_signed(core, signer))
    evidence = TimestampEvidence(
        request_b64=base64.b64encode(request).decode(),
        response_b64=base64.b64encode(response).decode(),
    )
    return subject, evidence, policy, authority


def test_real_RFC3161_signature_imprint_nonce_and_accuracy(real_timestamp):
    subject, evidence, policy, authority = real_timestamp
    interval = verify_timestamp(
        subject, evidence, policy=policy, trust_store=authority["trust_store"]
    )
    assert interval.upper - interval.lower == timedelta(seconds=2)
    assert interval.lower <= datetime.now(UTC) + timedelta(seconds=2)


@pytest.mark.parametrize(
    "mutation", ["imprint", "nonce", "policy", "trust", "accuracy", "signature"]
)
def test_real_RFC3161_rejects_mutations(real_timestamp, mutation):
    subject, evidence, policy, authority = real_timestamp
    trust = authority["trust_store"]
    if mutation == "imprint":
        subject += b"changed"
    elif mutation == "nonce":
        evidence = evidence.model_copy(
            update={"request_b64": base64.b64encode(_openssl_query(subject)).decode()}
        )
    elif mutation == "policy":
        policy = policy.model_copy(
            update={"core": policy.core.model_copy(update={"tsa_policy_oid": "1.2.3.999"})}
        )
    elif mutation == "trust":
        trust = b"not the pinned authority"
    elif mutation == "accuracy":
        policy = policy.model_copy(
            update={"core": policy.core.model_copy(update={"maximum_accuracy_microseconds": 1})}
        )
    else:
        data = bytearray(base64.b64decode(evidence.response_b64))
        data[-1] ^= 1
        evidence = evidence.model_copy(update={"response_b64": base64.b64encode(data).decode()})
    with pytest.raises(ValueError):
        verify_timestamp(subject, evidence, policy=policy, trust_store=trust)


@pytest.mark.parametrize(
    "value",
    [
        "unspecified",
        "unspecified seconds, unspecified millis, unspecified micros",
        "0x01 seconds, 0xFFFF millis, unspecified micros",
    ],
)
def test_no_implicit_or_invalid_accuracy(value):
    with pytest.raises(ValueError):
        _accuracy(value)


def test_accuracy_parses_milliseconds_and_microseconds():
    assert _accuracy("0x01 seconds, 0x01F4 millis, 0x01 micros") == timedelta(
        microseconds=1_500_001
    )
