"""Zeek JSONL acquisition and signed batch construction."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

from .canonical import GENESIS_CHAIN_HASH, batch_chain_hash, digest_object, sha256_bytes
from .crypto import DigestSigner
from .models import AttestationResult, BatchManifest, BatchManifestCore, SignatureBlock
from .storage import atomic_write, utc_now


@dataclass(frozen=True)
class BuiltBatch:
    raw: bytes
    manifest: BatchManifest
    queue_directory: Path


def _zeek_timestamp_to_utc(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("Zeek event timestamp must be numeric")
    try:
        timestamp = float(value)
    except ValueError as exc:
        raise ValueError("Zeek event timestamp must be numeric") from exc
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat().replace("+00:00", "Z")


def inspect_zeek_jsonl(raw: bytes) -> tuple[int, str, str]:
    timestamps: list[str] = []
    count = 0
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON on Zeek line {line_number}: {exc.msg}") from exc
        if not isinstance(event, dict) or "ts" not in event:
            raise ValueError(f"Zeek line {line_number} is missing the ts field")
        timestamps.append(_zeek_timestamp_to_utc(event["ts"]))
        count += 1
    if not timestamps:
        raise ValueError("cannot close an empty Zeek batch")
    return count, min(timestamps), max(timestamps)


def build_batch(
    *,
    input_path: Path,
    queue_root: Path,
    node_id: str,
    client_id: str,
    session_id: str,
    sequence_number: int,
    attestation: AttestationResult,
    signer: DigestSigner,
    configuration_digest: str,
    previous_chain_hash: str = GENESIS_CHAIN_HASH,
    collector_id: str = "zeek-acquisition-agent",
    collector_version: str = "0.1.0",
    trust_level: str = "software-development",
) -> BuiltBatch:
    raw = input_path.read_bytes()
    record_count, observed_start, observed_end = inspect_zeek_jsonl(raw)
    content_sha256 = sha256_bytes(raw)
    batch_id = f"batch-{client_id}-{session_id}-{sequence_number:06d}"
    attestation_digest = digest_object(attestation.model_dump(mode="json"))
    collector_digest = sha256_bytes(f"{collector_id}:{collector_version}".encode("utf-8"))
    core = BatchManifestCore(
        batch_id=batch_id,
        node_id=node_id,
        client_id=client_id,
        acquisition_session_id=session_id,
        sequence_number=sequence_number,
        source_type="zeek-jsonl",
        source_name=input_path.name,
        observed_start=observed_start,
        observed_end=observed_end,
        acquired_at=utc_now(),
        record_count=record_count,
        content_filename=input_path.name,
        content_size_bytes=len(raw),
        content_sha256=content_sha256,
        previous_chain_hash=previous_chain_hash,
        collector_id=collector_id,
        collector_version=collector_version,
        collector_digest=collector_digest,
        configuration_digest=configuration_digest,
        attestation_id=attestation.result_id,
        attestation_digest=attestation_digest,
    )
    core_dict = core.model_dump(mode="json")
    core_digest = digest_object(core_dict)
    chain_hash = batch_chain_hash(previous_chain_hash, content_sha256, core_dict)
    manifest = BatchManifest(
        core=core,
        canonical_core_sha256=core_digest,
        chain_hash=chain_hash,
        signature=SignatureBlock(
            key_id=signer.key_id,
            value_b64=signer.sign_digest(chain_hash),
            trust_level=trust_level,
        ),
    )

    final_directory = queue_root / batch_id
    if final_directory.exists():
        raise FileExistsError(f"batch queue entry already exists: {final_directory}")
    staging = queue_root / f".{batch_id}.staging"
    staging.mkdir(parents=True, exist_ok=False)
    atomic_write(staging / input_path.name, raw)
    atomic_write(
        staging / "manifest.json",
        json.dumps(
            manifest.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n",
    )
    staging.replace(final_directory)
    return BuiltBatch(raw=raw, manifest=manifest, queue_directory=final_directory)

