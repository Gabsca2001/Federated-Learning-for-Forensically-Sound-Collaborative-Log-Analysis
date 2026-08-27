"""Download and bind the official five-file UWF-ZeekData22 CSV subset."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

BASE_URL = "https://datasets.uwf.edu/data/UWF-ZeekData22/csv"
FILES: tuple[dict[str, Any], ...] = (
    {
        "filename": "part-00000-0af89d10-df53-44fd-b124-a8a496fd5023-c000.csv",
        "size_bytes": 4_530_213,
    },
    {
        "filename": "part-00000-15e3dd03-ea76-429e-a52a-ce96a90517f9-c000.csv",
        "size_bytes": 2_057_705,
    },
    {
        "filename": "part-00000-318611a1-7cdc-4dd0-9348-c6368917fd0c-c000.csv",
        "size_bytes": 2_012_939,
    },
    {
        "filename": "part-00000-5b4f5c3f-e8a9-4020-8fa1-e8985f7c27f3-c000.csv",
        "size_bytes": 196_337_021,
    },
    {
        "filename": "part-00000-95e0a460-e7c5-4b35-8367-c2e6fbbcf9e1-c000.csv",
        "size_bytes": 197_216_207,
    },
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download_atomic(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        request = urllib.request.Request(
            url, headers={"User-Agent": "fl-forensics-pipeline/0.5"}
        )
        with urllib.request.urlopen(request) as response, temporary.open("wb") as output:
            while block := response.read(1024 * 1024):
                output.write(block)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _existing_manifest(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return value if value.get("dataset") == "UWF-ZeekData22" else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw/uwf-zeekdata22/csv"),
        help="Destination directory (default: %(default)s)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify existing files against their controlled-ingestion manifest",
    )
    arguments = parser.parse_args()

    manifest_path = arguments.output / "download_manifest.json"
    previous = _existing_manifest(manifest_path)
    if arguments.verify_only and previous is None:
        raise RuntimeError(f"missing valid controlled-ingestion manifest: {manifest_path}")
    previous_records = {
        str(item["relative_path"]): item for item in (previous or {}).get("files", [])
    }
    records: list[dict[str, Any]] = []
    for expected in FILES:
        filename = str(expected["filename"])
        destination = arguments.output / filename
        url = f"{BASE_URL}/{filename}"
        if not destination.is_file():
            if arguments.verify_only:
                raise RuntimeError(f"missing controlled Data22 source: {destination}")
            print(f"Downloading {url}", flush=True)
            download_atomic(url, destination)
        size = destination.stat().st_size
        if size != int(expected["size_bytes"]):
            raise RuntimeError(
                f"size mismatch for {filename}: expected {expected['size_bytes']}, got {size}"
            )
        digest = sha256_file(destination)
        if previous is not None:
            bound = previous_records.get(filename)
            if bound is None or int(bound.get("size_bytes", -1)) != size:
                raise RuntimeError(f"existing manifest does not bind {filename}")
            if str(bound.get("sha256")) != digest:
                raise RuntimeError(f"existing manifest SHA-256 mismatch for {filename}")
        records.append(
            {
                "relative_path": filename,
                "source_url": url,
                "size_bytes": size,
                "sha256": digest,
            }
        )

    manifest = {
        "schema_version": "1.0",
        "dataset": "UWF-ZeekData22",
        "source_format": "csv",
        "source_release": "official-five-file-csv-subset",
        "controlled_ingestion_at": (previous or {}).get("controlled_ingestion_at")
        or datetime.now(UTC).isoformat(),
        "files": records,
    }
    if previous is not None and previous != manifest:
        raise RuntimeError("existing manifest differs from the verified Data22 source set")
    if not arguments.verify_only:
        arguments.output.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {len(records)} Data22 CSV files; manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
