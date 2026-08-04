"""Download the official UWF-ZeekData24 CSV development release reproducibly."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

BASE_URL = "https://datasets.uwf.edu/data/UWF-ZeekData24/csv"
FILES = {
    "Benign": "part-00000-b039213f-1208-4f1b-b71d-5e8e3a4a2939-c000.csv",
    "Credential_Access": "part-00000-912fdc44-5727-4d42-8fd6-a0e206ba29f8-c000.csv",
    "Defense_Evasion": "part-00000-de4985c7-284a-4b6e-b507-e69a2d172582-c000.csv",
    "Exfiltration": "part-00000-6a530c25-0f6b-46a1-ba16-c6b658ef75e8-c000.csv",
    "Initial_Access": "part-00000-9a37b839-429e-444b-82a5-a6d5e69dad7e-c000.csv",
    "Persistence": "part-00000-fb5a764a-e65e-4e10-b6fb-1a189589d5e0-c000.csv",
    "Privilege_Escalation": "part-00000-d8fcf83a-aed1-4cb1-babf-581208088293-c000.csv",
    "Reconnaissance": "part-00000-49ed1cc6-3205-4c76-8e28-4da9abf78363-c000.csv",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download_atomic(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "fl-forensics-pipeline/0.1"})
        with urllib.request.urlopen(request) as response, temporary.open("wb") as output:
            while block := response.read(1024 * 1024):
                output.write(block)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw/uwf-zeekdata24/csv"),
        help="Destination directory (default: %(default)s)",
    )
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    manifest_path = args.output / "download_manifest.json"
    previous_ingestion_time = None
    if manifest_path.is_file():
        try:
            previous_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if previous_manifest.get("dataset") == "UWF-ZeekData24":
                previous_ingestion_time = previous_manifest.get("controlled_ingestion_at")
        except (json.JSONDecodeError, OSError):
            previous_ingestion_time = None

    records = []
    missing = []
    for label, filename in FILES.items():
        destination = args.output / label / filename
        url = f"{BASE_URL}/{label}/{filename}"
        if not destination.exists():
            if args.verify_only:
                missing.append(str(destination))
                continue
            print(f"Downloading {label}: {url}")
            download_atomic(url, destination)

        records.append(
            {
                "label": label,
                "relative_path": destination.relative_to(args.output).as_posix(),
                "source_url": url,
                "size_bytes": destination.stat().st_size,
                "sha256": sha256_file(destination),
            }
        )

    if missing:
        for path in missing:
            print(f"MISSING: {path}")
        return 1

    manifest = {
        "schema_version": "1.0",
        "dataset": "UWF-ZeekData24",
        "controlled_ingestion_at": previous_ingestion_time
        or datetime.now(UTC).isoformat(),
        "files": records,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {len(records)} files; manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
