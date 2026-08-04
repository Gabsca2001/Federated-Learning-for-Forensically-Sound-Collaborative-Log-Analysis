"""Canonical JSON and digest primitives used by signed artifacts.

Manifest cores deliberately use an integer-only subset of RFC 8785/JCS. This
keeps number serialization unambiguous across the initial Python prototype.
Floating-point measurements belong in derived data, not signed manifest cores;
when needed in a manifest they must be represented as decimal strings or scaled
integers with an explicit unit.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value is outside the signed-manifest canonical profile."""


def _validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise CanonicalizationError(
            f"floating-point value at {path}; use a decimal string or scaled integer"
        )
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string key at {path}")
            _validate(item, f"{path}.{key}")
        return
    raise CanonicalizationError(f"unsupported type {type(value).__name__} at {path}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a manifest value using the repository's strict JCS profile."""

    _validate(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_object(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def batch_chain_hash(previous_chain_hash: str, content_sha256: str, core: dict[str, Any]) -> str:
    """Calculate SHA256(prev || content || SHA256(JCS(core))) using binary digests."""

    try:
        previous = bytes.fromhex(previous_chain_hash)
        content = bytes.fromhex(content_sha256)
    except ValueError as exc:
        raise CanonicalizationError("chain inputs must be hexadecimal SHA-256 digests") from exc
    if len(previous) != 32 or len(content) != 32:
        raise CanonicalizationError("chain inputs must each be 32 bytes")
    core_digest = bytes.fromhex(digest_object(core))
    return sha256_bytes(previous + content + core_digest)


GENESIS_CHAIN_HASH = "0" * 64

