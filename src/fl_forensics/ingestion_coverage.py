"""Record coverage relative to authenticated, pre-transformation input bytes.

Each source occurrence has a distinct identity, including duplicates. A signed
inventory is written before transformation; a separate signed manifest binds
the outcomes and derived payloads. Verification re-executes the transformation.
Neither signature proves capture completeness or independently trusted time.
"""

from __future__ import annotations

import json
import math
import shutil
import sqlite3
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal

from pydantic import Field

from .canonical import digest_object, sha256_bytes, sha256_file
from .crypto import DigestSigner
from .models import HEX_256_PATTERN, SignatureBlock, StrictModel
from .preprocessing import derived_json_bytes, normalize_and_window
from .round_derivation import _signed, _verify_signature, implementation_sha256
from .storage import write_json_once, write_once

Profile = Literal["zeek-jsonl-v1", "data24-csv-v1", "data24-parquet-v1"]


class RecordCoverageError(ValueError):
    """The committed source occurrences are not fully accounted for."""


class RecordInventoryCore(StrictModel):
    domain: Literal["fl-record-inventory-v1"] = "fl-record-inventory-v1"
    profile: Profile
    source_anchor_sha256: str = Field(pattern=HEX_256_PATTERN)
    sources: dict[str, str]
    config_sha256: str = Field(pattern=HEX_256_PATTERN)
    records_sha256: str = Field(pattern=HEX_256_PATTERN)
    record_count: int = Field(ge=0)
    phase: Literal["before_transformation_replay"] = "before_transformation_replay"


class RecordInventory(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["record_input_inventory"] = "record_input_inventory"
    inventory_id: str
    core: RecordInventoryCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class RecordCoverageCore(StrictModel):
    domain: Literal["fl-record-coverage-v1"] = "fl-record-coverage-v1"
    inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    outcomes_sha256: str = Field(pattern=HEX_256_PATTERN)
    snapshot_artifacts: dict[str, str]
    outcome_counts: dict[str, int]
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)


class RecordCoverageManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["record_coverage_manifest"] = "record_coverage_manifest"
    manifest_id: str
    core: RecordCoverageCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


def _files(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RecordCoverageError("symbolic links are not committed payloads")
        if path.is_file():
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                raise RecordCoverageError("source or artifact escapes its root")
            result[path.relative_to(root).as_posix()] = sha256_file(path)
    return result


def _source_paths(source: Path, profile: str, anchor: str) -> list[tuple[str, Path]]:
    if profile == "zeek-jsonl-v1":
        if sha256_file(source) != anchor:
            raise RecordCoverageError("source anchor mismatch")
        return [("input.jsonl", source)]
    if sha256_file(source / "download_manifest.json") != anchor:
        raise RecordCoverageError("source anchor mismatch")
    if profile == "data24-parquet-v1":
        from .dataset24_parquet import verify_parquet_manifest

        _, files = verify_parquet_manifest(source)
    elif profile == "data24-csv-v1":
        from .dataset24 import verify_download_manifest

        _, files = verify_download_manifest(source)
    else:
        raise RecordCoverageError("unknown ingestion profile")
    return [("download_manifest.json", source / "download_manifest.json")] + [
        (item["relative_path"], source / item["relative_path"]) for item in files
    ]


def _records(root: Path, profile: str):
    """The file commitments define I0; enumerate every occurrence, not just values."""
    if profile == "zeek-jsonl-v1":
        for number, line in enumerate((root / "input.jsonl").read_bytes().splitlines(), 1):
            yield _record("input.jsonl", number, sha256_bytes(line), not line.strip())
        return
    if profile == "data24-parquet-v1":
        from .dataset24 import EXPECTED_COLUMNS, _full_row_digest
        from .dataset24_parquet import _iter_parquet_rows, _parquet, discover_parquet_files

        parquet = _parquet()
        for path in discover_parquet_files(root):
            for number, row in _iter_parquet_rows(path, parquet):
                yield _record(
                    path.relative_to(root).as_posix(),
                    number,
                    _full_row_digest(row, EXPECTED_COLUMNS),
                )
        return
    from .dataset24 import discover_csv_files

    for path in discover_csv_files(root):
        # The CSV header is schema, not an event. Empty data lines are explicit
        # discarded occurrences, including ones ignored by the legacy loader.
        with path.open("r", encoding="utf-8", newline="") as stream:
            next(stream)
            for number, line in enumerate(stream, 2):
                yield _record(
                    path.relative_to(root).as_posix(),
                    number,
                    sha256_bytes(line.encode()),
                    not line.strip(),
                )


def _record(path: str, position: int, digest: str, blank: bool = False) -> dict[str, Any]:
    core = {"source_path": path, "position": position, "record_sha256": digest, "blank": blank}
    return {"record_id": "record-" + digest_object(core), **core}


def _write_stream(path: Path, values: Any) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("xb") as stream:
        for value in values:
            stream.write(derived_json_bytes(value))
            count += 1
    return count


def _jsonlines(path: Path):
    with path.open("rb") as stream:
        for line in stream:
            yield json.loads(line)


def _derive(profile: str, inputs: Path, config: dict[str, Any], output: Path) -> None:
    if profile != "zeek-jsonl-v1":
        from .dataset24 import prepare_dataset

        prepare_dataset(source_root=inputs, output=output, preprocessing_config=config)
        return
    raw = (inputs / "input.jsonl").read_bytes()
    digest = sha256_bytes(raw)
    result = normalize_and_window(
        raw=raw,
        batch_id="ingested-" + digest,
        batch_digest=digest,
        client_id="ingestion",
        config=config,
    )
    for name, value in (
        ("dataset.json", {"rows": result.rows}),
        ("lineage.json", result.lineage),
        ("discards.json", result.discarded_records),
    ):
        write_once(output / name, derived_json_bytes(value))
    write_once(
        output / "normalized_events.jsonl",
        b"".join(derived_json_bytes(event) for event in result.normalized_events),
    )


def _jsonl_rejection(line: bytes, config: dict[str, Any]) -> str:
    from .preprocessing import _event_label, _finite_float

    if not line.strip():
        return "blank_line"
    try:
        source = json.loads(line)
    except (ValueError, UnicodeError):
        return "invalid_json"
    if not isinstance(source, dict) or "ts" not in source:
        return "missing_timestamp"
    if _finite_float(source["ts"], default=-1.0) < 0:
        return "invalid_timestamp"
    if _event_label(source, list(config["label_fields"])) is None:
        return "missing_label"
    if source.get("_source_records") is not None and not isinstance(
        source["_source_records"], list
    ):
        return "invalid_source_lineage"
    raise RecordCoverageError("valid source record has no derived event")


def _outcomes(inputs: Path, profile: str, config: dict[str, Any], snapshot: Path, database: Path):
    """Resolve all joins on disk; this also checks reference uniqueness."""
    rows = json.loads((snapshot / "dataset.json").read_bytes())["rows"]
    retained = {row["window_id"] for row in rows}
    if len(retained) != len(rows):
        raise RecordCoverageError("duplicate derived window")
    db = sqlite3.connect(database)
    try:
        db.execute("CREATE TABLE events (id TEXT PRIMARY KEY, window TEXT NOT NULL)")
        db.execute("CREATE TABLE members (event TEXT PRIMARY KEY, window TEXT NOT NULL)")
        for row in rows:
            db.executemany(
                "INSERT INTO members VALUES (?, ?)",
                [(event, row["window_id"]) for event in row["source_event_ids"]],
            )
        db.execute(
            "CREATE TABLE links (path TEXT, position INTEGER, digest TEXT NOT NULL, event TEXT NOT NULL, PRIMARY KEY(path, position))"
        )
        batch = []
        for event in _jsonlines(snapshot / "normalized_events.jsonl"):
            bucket = math.floor(event["timestamp"] / int(config["window_seconds"]))
            client = "ingestion" if profile == "zeek-jsonl-v1" else "central"
            identity = sha256_bytes(f"{event['capture_id']}:{bucket}".encode())[:20]
            batch.append((event["event_id"], f"window-{client}-{identity}"))
            if len(batch) == 10000:
                db.executemany("INSERT INTO events VALUES (?, ?)", batch)
                batch.clear()
        db.executemany("INSERT INTO events VALUES (?, ?)", batch)
        if profile == "data24-parquet-v1":
            lineage = (
                row
                for row in _jsonlines(snapshot / "lineage.jsonl")
                if row["record_type"] == "event"
            )
        else:
            data = json.loads((snapshot / "lineage.json").read_bytes())
            lineage = ({"event_id": event, **values} for event, values in data["events"].items())
        batch = []
        for event in lineage:
            if profile == "zeek-jsonl-v1":
                sources = [
                    {
                        "relative_path": "input.jsonl",
                        "line_number": event["source_line"],
                        "raw_line_sha256": event["raw_line_sha256"],
                    }
                ]
            else:
                sources = event["source_records"]
            for ref in sources:
                position = (
                    ref["row_number"] if profile == "data24-parquet-v1" else ref["line_number"]
                )
                digest = (
                    ref["source_record_sha256"]
                    if profile == "data24-parquet-v1"
                    else ref["raw_line_sha256"]
                )
                batch.append((ref["relative_path"], position, digest, event["event_id"]))
                if len(batch) == 10000:
                    db.executemany("INSERT INTO links VALUES (?, ?, ?, ?)", batch)
                    batch.clear()
        db.executemany("INSERT INTO links VALUES (?, ?, ?, ?)", batch)
        db.execute("CREATE INDEX links_event ON links(event)")
        db.commit()
        raw_lines = (
            (inputs / "input.jsonl").read_bytes().splitlines()
            if profile == "zeek-jsonl-v1"
            else None
        )
        referenced = 0
        for record in _records(inputs, profile):
            link = db.execute(
                "SELECT links.digest, links.event, events.window, members.window FROM links LEFT JOIN events ON events.id=links.event LEFT JOIN members ON members.event=events.id WHERE links.path=? AND links.position=?",
                (record["source_path"], record["position"]),
            ).fetchone()
            outcome = {"record_id": record["record_id"]}
            if link is None:
                reason = (
                    _jsonl_rejection(raw_lines[record["position"] - 1], config)
                    if raw_lines is not None
                    else "blank_line"
                    if record["blank"]
                    else None
                )
                if reason is None:
                    raise RecordCoverageError("uncovered committed source record")
                outcome.update(status="discarded", reason=reason, event_id=None, window_id=None)
            else:
                referenced += 1
                digest, event_id, window_id, member_window = link
                if digest != record["record_sha256"] or window_id is None or record["blank"]:
                    raise RecordCoverageError("source/event reference mismatch")
                if window_id in retained:
                    if member_window != window_id:
                        raise RecordCoverageError(
                            "retained window omits or misassigns its source event"
                        )
                    outcome.update(
                        status="derived", reason=None, event_id=event_id, window_id=window_id
                    )
                elif profile == "data24-parquet-v1" and config.get("training_sampling", {}).get(
                    "enabled"
                ):
                    outcome.update(
                        status="discarded",
                        reason="training_window_not_selected",
                        event_id=event_id,
                        window_id=window_id,
                    )
                else:
                    raise RecordCoverageError(
                        "derived event has no retained window or declared sampling outcome"
                    )
            yield outcome
        if db.execute(
            "SELECT COUNT(*) FROM members LEFT JOIN events ON members.event=events.id WHERE events.id IS NULL OR members.window != events.window"
        ).fetchone()[0]:
            raise RecordCoverageError("retained window cites an unknown or wrongly grouped event")
        if referenced != db.execute("SELECT COUNT(*) FROM links").fetchone()[0]:
            raise RecordCoverageError("extra source reference outside committed inventory")
        if db.execute(
            "SELECT COUNT(*) FROM events WHERE id NOT IN (SELECT event FROM links)"
        ).fetchone()[0]:
            raise RecordCoverageError("derived event lacks a committed source")
    except sqlite3.IntegrityError as exc:
        raise RecordCoverageError("duplicate source occurrence or event reference") from exc
    finally:
        db.close()


def _summary(
    workspace: Path, inventory: RecordInventory, manifest: RecordCoverageManifest
) -> dict[str, Any]:
    return {
        "status": "verified",
        "profile": inventory.core.profile,
        "inventory_sha256": sha256_file(workspace / "input-inventory.json"),
        "manifest_sha256": sha256_file(workspace / "manifest.json"),
        "record_count": inventory.core.record_count,
        "outcome_counts": manifest.core.outcome_counts,
        "nontrivial_coverage_verified": inventory.core.record_count > 0,
        "scope": "every occurrence in the pinned input files; duplicate values remain distinct occurrences",
        "snapshot_recomputed": True,
        "capture_completeness_verified": False,
        "independent_timestamp_verified": False,
        "historical_inventory_preexistence_verified": False,
    }


def create_ingestion_coverage(
    *,
    output: Path,
    source: Path,
    profile: str,
    expected_source_sha256: str,
    preprocessing_config: dict[str, Any],
    signer: DigestSigner,
    authority_public_key: Any,
) -> dict[str, Any]:
    if output.exists():
        raise RecordCoverageError("use a new workspace; never overwrite a closed ingestion")
    if output.resolve().is_relative_to(source.resolve()) or source.resolve().is_relative_to(
        output.resolve()
    ):
        raise RecordCoverageError("keep the ingestion workspace outside the source")
    paths = _source_paths(source, profile, expected_source_sha256)
    for relative, original in paths:
        destination = output / "inputs" / relative
        if not destination.resolve().is_relative_to((output / "inputs").resolve()):
            raise RecordCoverageError("unsafe source path")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
        if sha256_file(original) != sha256_file(destination):
            raise RecordCoverageError("source changed during snapshot")
    inputs = output / "inputs"
    frozen_source = inputs / "input.jsonl" if profile == "zeek-jsonl-v1" else inputs
    _source_paths(frozen_source, profile, expected_source_sha256)
    config_data = derived_json_bytes(preprocessing_config)
    write_once(output / "preprocessing-config.json", config_data)
    preprocessing_config = json.loads(config_data)
    count = _write_stream(output / "source-records.jsonl", _records(inputs, profile))
    inventory = _signed(
        RecordInventory,
        RecordInventoryCore(
            profile=profile,
            source_anchor_sha256=expected_source_sha256,
            sources=_files(inputs),
            config_sha256=sha256_bytes(config_data),
            records_sha256=sha256_file(output / "source-records.jsonl"),
            record_count=count,
        ),
        "inventory_id",
        "record-inventory-",
        signer,
    )
    _verify_signature(inventory, authority_public_key, "inventory_id", "record-inventory-")
    write_json_once(output / "input-inventory.json", inventory.model_dump(mode="json"))
    # This write is deliberately before the first transformation call.
    _derive(profile, inputs, preprocessing_config, output / "snapshot")
    with TemporaryDirectory(prefix="fl-record-coverage-") as temporary:
        counts: Counter[str] = Counter()

        def outcomes():
            for outcome in _outcomes(
                inputs,
                profile,
                preprocessing_config,
                output / "snapshot",
                Path(temporary) / "joins.sqlite",
            ):
                counts[outcome["reason"] if outcome["status"] == "discarded" else "derived"] += 1
                yield outcome

        outcome_count = _write_stream(output / "record-outcomes.jsonl", outcomes())
    if outcome_count != count or _files(inputs) != inventory.core.sources:
        raise RecordCoverageError("input mutation or incomplete outcome partition")
    manifest = _signed(
        RecordCoverageManifest,
        RecordCoverageCore(
            inventory_sha256=sha256_file(output / "input-inventory.json"),
            outcomes_sha256=sha256_file(output / "record-outcomes.jsonl"),
            snapshot_artifacts=_files(output / "snapshot"),
            outcome_counts=dict(counts),
            implementation_sha256=implementation_sha256(),
        ),
        "manifest_id",
        "record-coverage-",
        signer,
    )
    _verify_signature(manifest, authority_public_key, "manifest_id", "record-coverage-")
    write_json_once(output / "manifest.json", manifest.model_dump(mode="json"))
    return {
        **_summary(output, inventory, manifest),
        "status": "created",
        "snapshot_recomputed": False,
    }


def verify_ingestion_coverage(
    *,
    workspace: Path,
    expected_inventory_sha256: str,
    expected_manifest_sha256: str,
    authority_public_key: Any,
) -> dict[str, Any]:
    try:
        inventory_data = (workspace / "input-inventory.json").read_bytes()
        manifest_data = (workspace / "manifest.json").read_bytes()
        if (
            sha256_bytes(inventory_data) != expected_inventory_sha256
            or sha256_bytes(manifest_data) != expected_manifest_sha256
        ):
            raise RecordCoverageError("trusted inventory or manifest pin mismatch")
        inventory = RecordInventory.model_validate_json(inventory_data)
        manifest = RecordCoverageManifest.model_validate_json(manifest_data)
        _verify_signature(inventory, authority_public_key, "inventory_id", "record-inventory-")
        _verify_signature(manifest, authority_public_key, "manifest_id", "record-coverage-")
        if manifest.core.inventory_sha256 != expected_inventory_sha256:
            raise RecordCoverageError("coverage is bound to another inventory")
        if manifest.core.implementation_sha256 != implementation_sha256():
            raise RecordCoverageError("use the preserved source release to verify this ingestion")
        inputs = workspace / "inputs"
        if _files(inputs) != inventory.core.sources:
            raise RecordCoverageError("committed source file set changed")
        source = inputs / "input.jsonl" if inventory.core.profile == "zeek-jsonl-v1" else inputs
        _source_paths(source, inventory.core.profile, inventory.core.source_anchor_sha256)
        config_data = (workspace / "preprocessing-config.json").read_bytes()
        if sha256_bytes(config_data) != inventory.core.config_sha256:
            raise RecordCoverageError("changed transformation policy")
        config = json.loads(config_data)
        if _files(workspace / "snapshot") != manifest.core.snapshot_artifacts:
            raise RecordCoverageError("changed or missing derived artifacts")
        if sha256_file(workspace / "source-records.jsonl") != inventory.core.records_sha256:
            raise RecordCoverageError("changed record inventory")
        if sha256_file(workspace / "record-outcomes.jsonl") != manifest.core.outcomes_sha256:
            raise RecordCoverageError("changed record outcomes")
        with TemporaryDirectory(prefix="fl-verify-ingestion-") as temporary:
            replay = Path(temporary)
            # Consume a private snapshot of exactly the pinned source bytes,
            # avoiding separate hash/parse reads from mutable input locators.
            frozen_inputs = replay / "inputs"
            for relative, expected in inventory.core.sources.items():
                origin = inputs / relative
                destination = frozen_inputs / relative
                if not destination.resolve().is_relative_to(frozen_inputs.resolve()):
                    raise RecordCoverageError("unsafe committed source path")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(origin, destination)
                if sha256_file(destination) != expected:
                    raise RecordCoverageError("source mutation while freezing verification inputs")
            count = _write_stream(
                replay / "records.jsonl", _records(frozen_inputs, inventory.core.profile)
            )
            if (
                count != inventory.core.record_count
                or sha256_file(replay / "records.jsonl") != inventory.core.records_sha256
            ):
                raise RecordCoverageError("record inventory is not the complete committed input")
            _derive(inventory.core.profile, frozen_inputs, config, replay / "snapshot")
            if _files(replay / "snapshot") != manifest.core.snapshot_artifacts:
                raise RecordCoverageError(
                    "derived snapshot does not reproduce from committed inputs"
                )
            counts: Counter[str] = Counter()

            def outcomes():
                for outcome in _outcomes(
                    frozen_inputs,
                    inventory.core.profile,
                    config,
                    replay / "snapshot",
                    replay / "joins.sqlite",
                ):
                    counts[
                        outcome["reason"] if outcome["status"] == "discarded" else "derived"
                    ] += 1
                    yield outcome

            outcome_count = _write_stream(replay / "outcomes.jsonl", outcomes())
            if (
                outcome_count != count
                or counts != manifest.core.outcome_counts
                or sha256_file(replay / "outcomes.jsonl") != manifest.core.outcomes_sha256
            ):
                raise RecordCoverageError("record outcomes do not reproduce or fail coverage")
        if _files(inputs) != inventory.core.sources:
            raise RecordCoverageError("source mutation during verification")
        return _summary(workspace, inventory, manifest)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        ArithmeticError,
        sqlite3.Error,
    ) as exc:
        return {"status": "failed", "errors": [str(exc)]}
