"""Configuration loading with stable source-byte digests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .canonical import sha256_bytes


def load_yaml(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    value = yaml.safe_load(raw)
    if not isinstance(value, dict):
        raise ValueError(f"configuration root must be an object: {path}")
    return value, sha256_bytes(raw)

