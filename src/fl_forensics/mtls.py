"""Minimal private PKI and executable mTLS binding checks for M4."""

from __future__ import annotations

import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .canonical import sha256_bytes
from .storage import atomic_write


SERVER_DNS_NAME = "verifier.m4.internal"


def _private_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _public_der(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def certificate_sha256(certificate: x509.Certificate) -> str:
    return sha256_bytes(certificate.public_bytes(serialization.Encoding.DER))


def public_key_sha256(key: ec.EllipticCurvePublicKey) -> str:
    return sha256_bytes(_public_der(key))


def load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def initialize_private_pki(workspace: Path, *, lifetime_days: int = 365) -> dict[str, str]:
    """Create the experiment CA and verifier certificate without overwriting state."""

    pki = workspace / "pki"
    ca_key_path = pki / "ca.private.pem"
    ca_cert_path = pki / "ca.certificate.pem"
    server_key_path = pki / "verifier.private.pem"
    server_cert_path = pki / "verifier.certificate.pem"
    identity_paths = (ca_key_path, ca_cert_path, server_key_path, server_cert_path)
    if all(path.exists() for path in identity_paths):
        ca_cert = load_certificate(ca_cert_path)
        server_cert = load_certificate(server_cert_path)
        return {
            "ca_certificate_sha256": certificate_sha256(ca_cert),
            "server_certificate_sha256": certificate_sha256(server_cert),
        }
    if any(path.exists() for path in identity_paths):
        raise RuntimeError("partial M4 PKI exists; refusing to replace protected material")

    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FL Forensics M4 CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=lifetime_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = ec.generate_private_key(ec.SECP256R1())
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_DNS_NAME)])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=min(lifetime_days, 90)))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(SERVER_DNS_NAME)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    atomic_write(ca_key_path, _private_pem(ca_key))
    atomic_write(ca_cert_path, ca_cert.public_bytes(serialization.Encoding.PEM))
    atomic_write(server_key_path, _private_pem(server_key))
    atomic_write(server_cert_path, server_cert.public_bytes(serialization.Encoding.PEM))
    ca_key_path.chmod(0o600)
    server_key_path.chmod(0o600)
    return {
        "ca_certificate_sha256": certificate_sha256(ca_cert),
        "server_certificate_sha256": certificate_sha256(server_cert),
    }


def create_client_csr(node_workspace: Path, *, client_id: str, node_id: str) -> tuple[str, str]:
    private_path = node_workspace / "tls" / "client.private.pem"
    csr_path = node_workspace / "tls" / "client.csr.pem"
    if private_path.exists() and csr_path.exists():
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("client TLS key is not ECDSA")
        if public_key_sha256(csr.public_key()) != public_key_sha256(key.public_key()):
            raise ValueError("client TLS CSR does not match its private key")
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        expected_uri = f"urn:fl-forensics:client:{client_id}"
        if expected_uri not in san.get_values_for_type(x509.UniformResourceIdentifier):
            raise ValueError("existing client TLS CSR belongs to another client")
        return csr.public_bytes(serialization.Encoding.PEM).decode(), public_key_sha256(
            key.public_key()
        )
    if private_path.exists() or csr_path.exists():
        raise RuntimeError("partial client TLS identity exists")

    key = ec.generate_private_key(ec.SECP256R1())
    uri = x509.UniformResourceIdentifier(f"urn:fl-forensics:client:{client_id}")
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, client_id),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, node_id),
                ]
            )
        )
        .add_extension(x509.SubjectAlternativeName([uri]), critical=False)
        .sign(key, hashes.SHA256())
    )
    atomic_write(private_path, _private_pem(key))
    private_path.chmod(0o600)
    atomic_write(csr_path, csr.public_bytes(serialization.Encoding.PEM))
    return (
        csr.public_bytes(serialization.Encoding.PEM).decode(),
        public_key_sha256(key.public_key()),
    )


def issue_client_certificate(
    *,
    workspace: Path,
    node_workspace: Path,
    csr_pem: str,
    client_id: str,
    node_id: str,
    lifetime_days: int = 30,
) -> x509.Certificate:
    ca_key = serialization.load_pem_private_key(
        (workspace / "pki" / "ca.private.pem").read_bytes(), password=None
    )
    if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
        raise ValueError("M4 CA key is not ECDSA")
    ca_cert = load_certificate(workspace / "pki" / "ca.certificate.pem")
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("client TLS CSR signature is invalid")
    expected_uri = f"urn:fl-forensics:client:{client_id}"
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if expected_uri not in san.get_values_for_type(x509.UniformResourceIdentifier):
        raise ValueError("client TLS CSR does not bind the declared client")
    common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    units = csr.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    if (
        not common_names
        or common_names[0].value != client_id
        or not units
        or units[0].value != node_id
    ):
        raise ValueError("client TLS CSR subject does not bind the declared node")

    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=lifetime_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(expected_uri)]),
            False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        .sign(ca_key, hashes.SHA256())
    )
    atomic_write(
        node_workspace / "tls" / "client.certificate.pem",
        certificate.public_bytes(serialization.Encoding.PEM),
    )
    return certificate


def verify_client_certificate_binding(
    *,
    certificate: x509.Certificate,
    ca_certificate: x509.Certificate,
    client_id: str,
    expected_fingerprint: str,
    at_time: datetime | None = None,
) -> tuple[bool, str]:
    try:
        ca_public = ca_certificate.public_key()
        if not isinstance(ca_public, ec.EllipticCurvePublicKey):
            return False, "CA public key is not ECDSA"
        ca_public.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
        now = at_time or datetime.now(UTC)
        if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc):
            return False, "client certificate is outside its validity period"
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
            return False, "clientAuth EKU is missing"
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uri = f"urn:fl-forensics:client:{client_id}"
        if uri not in san.get_values_for_type(x509.UniformResourceIdentifier):
            return False, "certificate SAN does not bind the claimed client"
        if certificate_sha256(certificate) != expected_fingerprint:
            return False, "certificate fingerprint does not match enrollment"
        return True, "certificate chain, purpose, identity, and fingerprint verified"
    except Exception as exc:  # pragma: no cover - defensive certificate parser path
        return False, f"client certificate validation failed: {exc}"


def exercise_mtls_handshake(
    *,
    workspace: Path,
    node_workspace: Path,
    claimed_client_id: str,
    expected_fingerprint: str,
) -> dict[str, Any]:
    """Perform a real loopback TLS 1.3 handshake and bind the peer certificate."""

    ca_path = workspace / "pki" / "ca.certificate.pem"
    server_cert = workspace / "pki" / "verifier.certificate.pem"
    server_key = workspace / "pki" / "verifier.private.pem"
    client_cert = node_workspace / "tls" / "client.certificate.pem"
    client_key = node_workspace / "tls" / "client.private.pem"

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    outcome: dict[str, Any] = {}

    def serve() -> None:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_cert_chain(str(server_cert), str(server_key))
            context.load_verify_locations(cafile=str(ca_path))
            connection, _address = listener.accept()
            with context.wrap_socket(connection, server_side=True) as secured:
                peer_der = secured.getpeercert(binary_form=True)
                peer = x509.load_der_x509_certificate(peer_der)
                valid, detail = verify_client_certificate_binding(
                    certificate=peer,
                    ca_certificate=load_certificate(ca_path),
                    client_id=claimed_client_id,
                    expected_fingerprint=expected_fingerprint,
                )
                outcome.update(
                    {
                        "tls_version": secured.version(),
                        "peer_certificate_sha256": certificate_sha256(peer),
                        "binding_valid": valid,
                        "detail": detail,
                    }
                )
                secured.recv(1)
                secured.sendall(b"1" if valid else b"0")
        except Exception as exc:  # pragma: no cover - defensive transport path
            outcome.update({"binding_valid": False, "detail": str(exc)})
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_3
    client_context.load_verify_locations(cafile=str(ca_path))
    client_context.load_cert_chain(str(client_cert), str(client_key))
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        with client_context.wrap_socket(connection, server_hostname=SERVER_DNS_NAME) as secured:
            secured.sendall(b"?")
            outcome["server_response"] = secured.recv(1).decode()
    thread.join(timeout=5)
    return outcome
