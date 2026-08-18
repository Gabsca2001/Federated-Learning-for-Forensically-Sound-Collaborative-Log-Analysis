"""Download and verify the pinned official UWF-ZeekData24 Parquet release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


BASE_URL = "https://datasets.uwf.edu/data/UWF-ZeekData24/parquet"
FILES: tuple[dict[str, Any], ...] = (
    {
        "period": "2024-02-25 - 2024-03-03",
        "filename": "part-00000-8b838a85-76eb-4896-a0b6-2fc425e828c2-c000.snappy.parquet",
        "size_bytes": 18_779_592,
        "sha256": "4d833656b31d4d360691c2178c5c4d1b3c31f01db12c59f6779a08d55e5f0cc7",
    },
    {
        "period": "2024-03-03 - 2024-03-10",
        "filename": "part-00000-0955ed97-8460-41bd-872a-7375a7f0207e-c000.snappy.parquet",
        "size_bytes": 3_733_862,
        "sha256": "5a085f2749556f2c711af6f9c2bca9d43b3f19bb43696ef9194869f4ea69eb21",
    },
    {
        "period": "2024-03-10 - 2024-03-17",
        "filename": "part-00000-071774ae-97f3-4f31-9700-8bfcdf41305a-c000.snappy.parquet",
        "size_bytes": 12_282_299,
        "sha256": "47bceaf2dd16aee21bd774513fa4549616c066bbe4a20e42f55378f688d9b414",
    },
    {
        "period": "2024-03-17 - 2024-03-24",
        "filename": "part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet",
        "size_bytes": 27_802_118,
        "sha256": "97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63",
    },
    {
        "period": "2024-03-24 - 2024-03-31",
        "filename": "part-00000-ea3a47a3-0973-4d6b-a3a2-8dd441ee7901-c000.snappy.parquet",
        "size_bytes": 7_834_447,
        "sha256": "f7e557a250502782c60b10b955e6d87724730be519006ce30418511bc5ecf512",
    },
    {
        "period": "2024-10-27 - 2024-11-03",
        "filename": "part-00000-69700ccb-c1c1-4763-beb7-cd0f1a61c268-c000.snappy.parquet",
        "size_bytes": 33_163_904,
        "sha256": "cadcaf2084ab599d31a530a8cd5f93e010804b9e91ca1e3f8f2631a45ece2575",
    },
    {
        "period": "2024-11-03 - 2024-11-10",
        "filename": "part-00000-f078acc1-ab56-40a6-a6e1-99d780645c57-c000.snappy.parquet",
        "size_bytes": 36_635_805,
        "sha256": "0a61b52c3527e6e2e2a5f277778752d89a8ab2bb03147da5aee5d923055ccb7a",
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
            url, headers={"User-Agent": "fl-forensics-pipeline/0.4"}
        )
        with urllib.request.urlopen(request) as response, temporary.open("wb") as output:
            while block := response.read(1024 * 1024):
                output.write(block)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _source_url(period: str, filename: str) -> str:
    encoded_period = urllib.parse.quote(period, safe="")
    return f"{BASE_URL}/{encoded_period}/{filename}"


def _verify(path: Path, record: dict[str, Any]) -> None:
    expected_size = int(record["size_bytes"])
    if path.stat().st_size != expected_size:
        raise RuntimeError(
            f"size mismatch for {path}: expected {expected_size}, got {path.stat().st_size}"
        )
    digest = sha256_file(path)
    if digest != record["sha256"]:
        raise RuntimeError(
            f"SHA-256 mismatch for {path}: expected {record['sha256']}, got {digest}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw/uwf-zeekdata24/parquet"),
        help="Destination directory (default: %(default)s)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify pinned files and the existing manifest without downloading or writing",
    )
    arguments = parser.parse_args()

    manifest_path = arguments.output / "download_manifest.json"
    previous_ingestion_time: str | None = None
    if manifest_path.is_file():
        try:
            previous = json.loads(manifest_path.read_text(encoding="utf-8"))
            if previous.get("dataset") == "UWF-ZeekData24":
                previous_ingestion_time = previous.get("controlled_ingestion_at")
        except (json.JSONDecodeError, OSError):
            previous_ingestion_time = None

    manifest_records: list[dict[str, Any]] = []
    for record in FILES:
        period = str(record["period"])
        filename = str(record["filename"])
        destination = arguments.output / period / filename
        url = _source_url(period, filename)
        if not destination.is_file():
            if arguments.verify_only:
                raise RuntimeError(f"missing pinned Parquet source: {destination}")
            print(f"Downloading {period}: {url}", flush=True)
            download_atomic(url, destination)
        _verify(destination, record)
        manifest_records.append(
            {
                "capture_period": period,
                "relative_path": destination.relative_to(arguments.output).as_posix(),
                "source_url": url,
                "size_bytes": int(record["size_bytes"]),
                "sha256": str(record["sha256"]),
            }
        )

    manifest = {
        "schema_version": "1.0",
        "dataset": "UWF-ZeekData24",
        "source_format": "parquet",
        "source_release": "official-weekly-2024",
        "controlled_ingestion_at": previous_ingestion_time
        or datetime.now(UTC).isoformat(),
        "files": manifest_records,
    }
    if arguments.verify_only:
        if not manifest_path.is_file():
            raise RuntimeError(f"missing download manifest: {manifest_path}")
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        comparable = dict(existing)
        comparable["controlled_ingestion_at"] = manifest["controlled_ingestion_at"]
        if comparable != manifest:
            raise RuntimeError("download manifest does not match the pinned Parquet release")
    else:
        arguments.output.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
    print(
        f"Verified {len(manifest_records)} pinned Parquet files; manifest: {manifest_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
