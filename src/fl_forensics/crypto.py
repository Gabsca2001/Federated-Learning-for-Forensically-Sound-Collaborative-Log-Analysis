"""ECDSA P-256 signing abstraction.

The software implementation is a development adapter. Future adapters invoke
the same interface through `swtpm` or a physical TPM without exporting the
private key.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .canonical import sha256_bytes


class DigestSigner(Protocol):
    @property
    def key_id(self) -> str: ...

    def sign_digest(self, digest_hex: str) -> str: ...


def _digest_bytes(digest_hex: str) -> bytes:
    try:
        value = bytes.fromhex(digest_hex)
    except ValueError as exc:
        raise ValueError("digest must be hexadecimal") from exc
    if len(value) != 32:
        raise ValueError("digest must be a SHA-256 value")
    return value


def public_key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"sha256:{sha256_bytes(der)}"


@dataclass(frozen=True)
class SoftwareECDSASigner:
    """Development-only ECDSA signer backed by a PEM file."""

    private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def generate(cls) -> "SoftwareECDSASigner":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def load(cls, path: Path) -> "SoftwareECDSASigner":
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise ValueError("expected an unencrypted ECDSA P-256 private key")
        return cls(key)

    @property
    def key_id(self) -> str:
        return public_key_id(self.private_key.public_key())

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign_digest(self, digest_hex: str) -> str:
        signature = self.private_key.sign(
            _digest_bytes(digest_hex),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        return base64.b64encode(signature).decode("ascii")


def load_public_key(pem: bytes) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("expected an ECDSA P-256 public key")
    return key


def verify_digest_signature(
    public_key: ec.EllipticCurvePublicKey, digest_hex: str, signature_b64: str
) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(
            signature,
            _digest_bytes(digest_hex),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        return True
    except (InvalidSignature, ValueError):
        return False

