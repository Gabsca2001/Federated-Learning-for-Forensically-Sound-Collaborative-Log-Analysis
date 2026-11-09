"""Build frozen-policy primary and duplicate-sensitivity windows, without training."""

import argparse
import csv
import io
import json
import shutil
import zipfile
from pathlib import Path

import numpy as np

try:
    from fl_forensics.ton_iot_windows import (
        WindowAccumulator,
        duplicate_projection,
        fold_duplicate_index,
    )
except ModuleNotFoundError as error:
    if error.name != "fl_forensics":
        raise
    from ton_iot_windows import WindowAccumulator, duplicate_projection, fold_duplicate_index
from revision_ton_iot_collection_preflight import DigestReader, native_path, sha_file


def write(path, value):
    path.write_text(
        json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n", encoding="utf-8"
    )


def run(index_path, preflight_path, protocol_path, output):
    protocol = json.loads(protocol_path.read_text())
    assert sha_file(index_path) == protocol["source_index_sha256"]
    assert sha_file(preflight_path) == protocol["preflight_sha256"]
    assert sha_file(Path(__file__)) == protocol["preparation_driver_sha256"]
    module_path = Path(WindowAccumulator.add.__code__.co_filename)
    assert sha_file(module_path) == protocol["window_module_sha256"]
    index = json.loads(index_path.read_text())
    preflight = json.loads(preflight_path.read_text())
    expected_total = preflight["scanned_rows"]
    accepted = preflight["usable_rows_under_explicit_category_policy"]
    output.mkdir(parents=True, exist_ok=False)
    scratch = (output / "scratch").resolve()
    scratch.mkdir()
    assert scratch.is_relative_to(output.resolve())
    dtype = np.dtype([("digest", "S32"), ("ordinal", "<u4"), ("label", "u1"), ("kind", "<u2")])
    assert expected_total < 2**32
    assert shutil.disk_usage(output).free > accepted * dtype.itemsize + 6 * 1024**3, (
        "Preserve six GiB free beyond the temporary duplicate index"
    )
    records = np.memmap(scratch / "projection-index.bin", mode="w+", dtype=dtype, shape=(accepted,))
    keep = np.memmap(scratch / "keepers.bin", mode="w+", dtype="u1", shape=(expected_total,))
    keep[:] = 0
    reports = {f["name"]: f for f in preflight["source_files"]}
    kinds = {name: 1 << n for n, name in enumerate(sorted(preflight["attack_type_counts"]))}
    columns = index["fields"]
    archives = {}
    verified_archives = set()

    def rows():
        ordinal = 0
        for entry in index["files"]:
            if entry["storage"] == "zip_entry":
                path = native_path(entry, "archive_path")
                if path not in archives:
                    if path not in verified_archives:
                        assert sha_file(path) == index["archive"]["sha256"]
                        verified_archives.add(path)
                    archives[path] = zipfile.ZipFile(path)
                raw = archives[path].open(entry["archive_entry"])
            else:
                raw = native_path(entry, "path").open("rb")
            hashed = DigestReader(raw)
            with (
                raw,
                io.TextIOWrapper(
                    io.BufferedReader(hashed, buffer_size=1024 * 1024),
                    encoding="utf-8-sig",
                    newline="",
                ) as stream,
            ):
                reader = csv.DictReader(stream)
                assert ",".join(reader.fieldnames) == entry["header"]
                rejected = {
                    r["record_number"]
                    for r in reports[entry["name"]]["rejected_occurrences_first10000"]
                }
                count = 0
                for number, row in enumerate(reader, 1):
                    count += 1
                    if number not in rejected:
                        yield ordinal, row, entry["name"]
                    ordinal += 1
                assert count == reports[entry["name"]]["rows"]
                assert (
                    hashed.byte_count == entry["bytes"]
                    and hashed.digest.hexdigest() == entry["sha256"]
                )
            print(
                json.dumps(
                    {
                        "status": "source_pass_verified",
                        "file": entry["name"],
                        "global_records": ordinal,
                    }
                ),
                flush=True,
            )
        assert ordinal == expected_total

    def serialize(windows, name):
        rows_out = [acc.finish(bucket, profile=name) for bucket, acc in sorted(windows.items())]
        value = {
            "dataset": "ToN-IoT",
            "feature_names": preflight["feature_names"],
            "window_seconds": 60,
            "profile": name,
            "source_index_sha256": sha_file(index_path),
            "protocol_sha256": sha_file(protocol_path),
            "rows": rows_out,
        }
        write(output / (name + "-windows.json"), value)
        print(
            json.dumps(
                {
                    "status": "windows_written",
                    "profile": name,
                    "windows": len(rows_out),
                    "records": sum(r["source_record_count"] for r in rows_out),
                }
            ),
            flush=True,
        )
        return {
            "window_count": len(rows_out),
            "retained_records": sum(r["source_record_count"] for r in rows_out),
            "binary_window_counts": {
                label: sum(r["label"] == label for r in rows_out) for label in ("benign", "attack")
            },
            "sha256": sha_file(output / (name + "-windows.json")),
        }

    try:
        windows = {}
        position = 0
        for ordinal, row, source in rows():
            bucket = int(float(row["ts"])) // 60
            if bucket not in windows:
                windows[bucket] = WindowAccumulator()
            windows[bucket].add(row, ordinal=ordinal, source_name=source)
            records[position] = (
                duplicate_projection(row, columns),
                ordinal,
                1 << int(float(row["label"])),
                kinds[row["type"].strip().lower()],
            )
            position += 1
        assert position == accepted
        primary = serialize(windows, "occurrence")
        del windows
        records.flush()
        before_sort_sha = sha_file(scratch / "projection-index.bin")
        print(
            json.dumps({"status": "sorting_duplicate_index", "bytes": records.nbytes}), flush=True
        )
        duplicates = fold_duplicate_index(records, keep)
        duplicates["unsorted_projection_index_sha256"] = before_sort_sha
        duplicates["keeper_bitmap_sha256"] = sha_file(scratch / "keepers.bin")
        duplicates["projection_policy"] = (
            "SHA-256 of length-prefixed raw UTF-8 common non-label source fields, excluding optional uid, label and type; never treated as physical-connection identity."
        )
        write(output / "duplicate-audit.json", duplicates)
        print(json.dumps(dict(status="duplicate_audit_complete", **duplicates)), flush=True)
        windows = {}
        retained = 0
        for ordinal, row, source in rows():
            flag = int(keep[ordinal])
            if not flag:
                continue
            bucket = int(float(row["ts"])) // 60
            if bucket not in windows:
                windows[bucket] = WindowAccumulator()
            windows[bucket].add(row, ordinal=ordinal, source_name=source, label_override=flag - 1)
            retained += 1
        assert retained == duplicates["projection_groups"]
        sensitivity = serialize(windows, "exact-projection")
        del windows
        summary = {
            "status": "windows_and_duplicate_sensitivity_prepared",
            "source_rows": expected_total,
            "rejected_occurrences": expected_total - accepted,
            "primary": primary,
            "sensitivity": sensitivity,
            "duplicates": duplicates,
            "protocol_sha256": sha_file(protocol_path),
            "source_data_modified": False,
            "model_evaluation_started": False,
            "administrative_independence_claimed": False,
        }
        write(output / "preparation-summary.json", summary)
    finally:
        for archive in archives.values():
            archive.close()
        records._mmap.close()
        keep._mmap.close()
    for name in ("projection-index.bin", "keepers.bin"):
        target = (scratch / name).resolve()
        assert target.is_relative_to(scratch) and target.is_file()
        target.unlink()
    scratch.rmdir()
    print(
        json.dumps(
            {
                "status": "preparation_complete",
                "summary": summary,
                "free_bytes": shutil.disk_usage(output).free,
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("index", "preflight", "protocol", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    run(args.index, args.preflight, args.protocol, args.output)
