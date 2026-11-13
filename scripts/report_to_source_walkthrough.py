"""Walk one M7 investigation case from the published report back to its source rows.

Read-only on data and results: the only file written is the walkthrough JSON.
Source rows are read with the existing reader
``fl_forensics.dataset24_parquet._iter_parquet_rows`` (row numbering starts at 1)
and record digests are recomputed with ``fl_forensics.dataset24``.

The verdict logic mirrors the frozen ``protocol.md`` in the output folder; the
protocol SHA-256 is checked before any source row is read.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from fl_forensics.canonical import sha256_bytes, sha256_file
from fl_forensics.dataset24 import EXPECTED_COLUMNS, _full_row_digest, _identity_digest
from fl_forensics.dataset24_parquet import _iter_parquet_rows, _parquet
from fl_forensics.investigation_report import _canonical_json_bytes as report_canonical_json_bytes

DEFAULT_CASE = "m7-investigation-case-498ee95ed92e641b997528a6"
EVALUATION_FIELDS = (
    "src_ip_zeek",
    "dest_ip_zeek",
    "dest_port_zeek",
    "proto",
    "service",
    "conn_state",
    "history",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "datetime",
)
UNESTABLISHED = frozenset({"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"})
ESTABLISHED = frozenset({"SF", "S1", "S2", "S3", "RSTO", "RSTR"})
PAYLOAD_CAP_BYTES = 1000
MAX_SPAN_SECONDS = 60.0


class DigestMismatch(ValueError):
    """A recomputed digest differs from the declared one."""


def require_digest(label: str, actual: str, expected: str) -> None:
    if actual != expected:
        raise DigestMismatch(f"{label}: expected {expected}, recomputed {actual}")


def verify_file(path: Path, *, sha256: str, size: int | None = None, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}: missing file {path}")
    if size is not None and path.stat().st_size != size:
        raise DigestMismatch(f"{label}: size {path.stat().st_size} != declared {size}")
    require_digest(label, sha256_file(path), sha256)


def read_rows(path: Path, row_numbers: Iterable[int]) -> dict[int, dict[str, str]]:
    """Return the requested 1-based rows using the repository Parquet reader."""
    wanted = set(row_numbers)
    if not wanted or min(wanted) < 1:
        raise ValueError("row numbers must be positive (1-based)")
    found: dict[int, dict[str, str]] = {}
    last = max(wanted)
    for row_number, row in _iter_parquet_rows(path, _parquet()):
        if row_number in wanted:
            found[row_number] = row
        if row_number >= last:
            break
    missing = wanted - set(found)
    if missing:
        raise ValueError(f"rows not present in {path.name}: {sorted(missing)}")
    return found


def check_record(row: dict[str, str], reference: dict[str, Any], identity: str | None) -> dict[str, Any]:
    """Recompute full-row and identity digests; raise DigestMismatch on any difference."""
    full = _full_row_digest(row, EXPECTED_COLUMNS)
    require_digest(f"row {reference['row_number']} source_record_sha256", full, reference["source_record_sha256"])
    result = {"source_record_sha256": full, "source_record_match": True}
    if identity is not None:
        ident = _identity_digest(row, EXPECTED_COLUMNS)
        require_digest(f"row {reference['row_number']} source_identity_sha256", ident, identity)
        result.update(source_identity_sha256=ident, source_identity_match=True)
    return result


def _number(value: str) -> float | None:
    if value is None or str(value).strip() in {"", "-"}:
        return None
    return float(value)


def summarize(records: list[dict[str, str]]) -> dict[str, Any]:
    states = Counter(r["conn_state"] for r in records)
    payloads, missing_bytes, missing_state = [], 0, 0
    both_directions = []
    for r in records:
        ob, rb = _number(r["orig_bytes"]), _number(r["resp_bytes"])
        if ob is None or rb is None:
            missing_bytes += 1
        payloads.append((ob or 0.0) + (rb or 0.0))
        both_directions.append((ob or 0.0) > 0 and (rb or 0.0) > 0)
        if not r["conn_state"].strip():
            missing_state += 1
    durations = [d for d in (_number(r["duration"]) for r in records) if d is not None]
    times = sorted(datetime.fromisoformat(r["datetime"]) for r in records)
    by_src: dict[str, dict[str, set]] = {}
    for r in records:
        entry = by_src.setdefault(r["src_ip_zeek"], {"dst": set(), "port": set()})
        entry["dst"].add(r["dest_ip_zeek"])
        entry["port"].add(r["dest_port_zeek"])
    return {
        "record_count": len(records),
        "distinct_originators": sorted(by_src),
        "distinct_destination_ips": sorted({r["dest_ip_zeek"] for r in records}),
        "distinct_destination_ports": sorted({r["dest_port_zeek"] for r in records}, key=lambda p: (len(p), p)),
        "proto_counts": dict(Counter(r["proto"] for r in records)),
        "service_counts": dict(Counter(r["service"] or "<empty>" for r in records)),
        "conn_state_counts": dict(states),
        "history_counts": dict(Counter(r["history"] or "<empty>" for r in records)),
        "unestablished_or_rejected_count": sum(states[s] for s in UNESTABLISHED),
        "established_count": sum(states[s] for s in ESTABLISHED),
        "established_with_bidirectional_payload_count": sum(
            1 for r, b in zip(records, both_directions) if r["conn_state"] in ESTABLISHED and b
        ),
        "payload_bytes_per_record": payloads,
        "payload_bytes_total": sum(payloads),
        "payload_bytes_median": statistics.median(payloads) if payloads else None,
        "payload_bytes_max": max(payloads) if payloads else None,
        "orig_pkts_total": sum(_number(r["orig_pkts"]) or 0 for r in records),
        "resp_pkts_total": sum(_number(r["resp_pkts"]) or 0 for r in records),
        "records_missing_byte_fields": missing_bytes,
        "records_missing_conn_state": missing_state,
        "duration_seconds": {
            "present": len(durations),
            "min": min(durations) if durations else None,
            "max": max(durations) if durations else None,
            "median": statistics.median(durations) if durations else None,
        },
        "time_first_utc": times[0].isoformat(),
        "time_last_utc": times[-1].isoformat(),
        "time_span_seconds": (times[-1] - times[0]).total_seconds(),
        "fan_out_by_originator": {
            k: {"destination_ips": len(v["dst"]), "destination_ports": len(v["port"])} for k, v in by_src.items()
        },
    }


def evaluate(summary: dict[str, Any], preconditions_ok: bool) -> dict[str, Any]:
    """Apply the frozen protocol criteria mechanically."""
    n = summary["record_count"]
    supported = {
        "S1_single_originator": len(summary["distinct_originators"]) == 1,
        "S2_fan_out": len(summary["distinct_destination_ips"]) >= 2 or len(summary["distinct_destination_ports"]) >= 2,
        "S3_majority_unestablished": summary["unestablished_or_rejected_count"] >= 4,
        "S4_low_payload": summary["payload_bytes_median"] == 0 and summary["payload_bytes_max"] <= PAYLOAD_CAP_BYTES,
        "S5_within_window": summary["time_span_seconds"] <= MAX_SPAN_SECONDS,
    }
    fan = summary["fan_out_by_originator"].values()
    contested = {
        "C1_majority_established_with_payload": summary["established_with_bidirectional_payload_count"] >= 4,
        "C2_single_target_established": (
            len(summary["distinct_destination_ips"]) == 1
            and len(summary["distinct_destination_ports"]) == 1
            and summary["established_count"] > n / 2
        ),
        "C3_mixed_sources_no_fan_out": (
            len(summary["distinct_originators"]) >= 2
            and not any(v["destination_ips"] >= 2 or v["destination_ports"] >= 2 for v in fan)
        ),
    }
    missing_too_many = (
        summary["records_missing_conn_state"] > 2 or summary["records_missing_byte_fields"] > 2
    )
    all_supported, any_contested = all(supported.values()), any(contested.values())
    if not preconditions_ok:
        verdict, reason = "inconclusive", "evidence-chain precondition failed"
    elif missing_too_many:
        verdict, reason = "inconclusive", "more than 2 records lack conn_state or byte fields"
    elif all_supported and any_contested:
        verdict, reason = "inconclusive", "supported and contested conditions both hold"
    elif all_supported:
        verdict, reason = "supported", "all S1-S5 hold and no C condition holds"
    elif any_contested:
        verdict, reason = "contested", "at least one C condition holds"
    else:
        verdict, reason = "inconclusive", "neither the full S set nor any C condition holds"
    return {
        "supported_criteria": supported,
        "contested_criteria": contested,
        "records_missing_too_many_fields": missing_too_many,
        "verdict": verdict,
        "reason": reason,
        "scope": "compatibility of referenced records with a reconnaissance-style probing pattern; "
        "not a confirmation of malicious activity",
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = args.output.parent
    protocol = out_dir / "protocol.md"
    recorded = (out_dir / "protocol.sha256").read_text().split()[0]
    require_digest("protocol.md", sha256_file(protocol), recorded)

    m7 = args.report_dir
    manifest = json.loads((m7 / "manifest.json").read_text())
    core = manifest["core"]
    verify_file(m7 / "investigation-report.json", sha256=core["investigation_report_sha256"], label="investigation-report.json")
    verify_file(m7 / "report.md", sha256=core["report_markdown_sha256"], label="report.md")
    # Same serializer the report builder uses (investigation_report.py:68, :2369-2381).
    core_digest = sha256_bytes(report_canonical_json_bytes(core))
    require_digest("manifest canonical core", core_digest, manifest["canonical_core_sha256"])
    if not manifest["investigation_report_bundle_id"].endswith(core_digest[:24]):
        raise DigestMismatch("bundle id does not carry the canonical core prefix")

    report = json.loads((m7 / "investigation-report.json").read_text())
    case = next(c for c in report["cases"] if c["case_id"] == args.case)
    report_md = (m7 / "report.md").read_text()
    if f"### Case {args.case}" not in report_md:
        raise ValueError("case section missing from report.md")

    dataset_manifest = json.loads((args.source_root / "download_manifest.json").read_text())
    pinned = {f["relative_path"]: f for f in dataset_manifest["files"]}

    events, file_checks, records = [], {}, []
    references = [(e, r) for e in case["primary_evidence"]["events"] for r in e["source_records"]]
    by_file: dict[str, list] = {}
    for event, ref in references:
        by_file.setdefault(ref["relative_path"], []).append((event, ref))
    for relative, items in by_file.items():
        path = args.source_root / relative
        declared = items[0][1]
        if any(r["source_file_sha256"] != declared["source_file_sha256"] for _, r in items):
            raise DigestMismatch(f"inconsistent declared file digests for {relative}")
        pin = pinned[relative]
        require_digest(f"{relative} report-vs-dataset-manifest", declared["source_file_sha256"], pin["sha256"])
        verify_file(path, sha256=declared["source_file_sha256"], size=declared["source_file_size_bytes"], label=relative)
        file_checks[relative] = {
            "sha256": declared["source_file_sha256"],
            "size_bytes": declared["source_file_size_bytes"],
            "matches_report": True,
            "matches_dataset_manifest": pin["size_bytes"] == declared["source_file_size_bytes"],
        }
        rows = read_rows(path, [r["row_number"] for _, r in items])
        for event, ref in items:
            row = rows[ref["row_number"]]
            check = check_record(row, ref, event.get("source_identity_sha256"))
            fields = {k: row[k] for k in EVALUATION_FIELDS}
            records.append(fields)
            events.append(
                {
                    "event_id": event["event_id"],
                    "relative_path": relative,
                    "row_number": ref["row_number"],
                    "declared_source_record_sha256": ref["source_record_sha256"],
                    **check,
                    "fields": fields,
                }
            )

    summary = summarize(records)
    assessment = evaluate(summary, preconditions_ok=True)
    return {
        "artifact_type": "report_to_source_walkthrough",
        "schema_version": "1.0",
        "case_id": args.case,
        "protocol_sha256": recorded,
        "producer_script_sha256": sha256_file(Path(__file__)),
        "report": {
            "manifest_sha256": sha256_file(m7 / "manifest.json"),
            "investigation_report_sha256": core["investigation_report_sha256"],
            "report_markdown_sha256": core["report_markdown_sha256"],
            "canonical_core_sha256": core_digest,
            "manifest_digests_verified": True,
        },
        "case_model_outputs_not_evidence": {
            "predicted_class": case["model_measurement"]["predicted_class"],
            "confidence": case["model_measurement"]["confidence"],
            "attack_tactic_candidates": case["attack_interpretation"]["tactic_candidates"],
            "top_ig_features": [f["feature_name"] for f in case["explanation"]["integrated_gradients"]["top_features"]],
            "window_id": case["identity"]["window_id"],
        },
        "reader": "fl_forensics.dataset24_parquet._iter_parquet_rows (1-based row numbers)",
        "source_files": file_checks,
        "events": sorted(events, key=lambda e: e["row_number"]),
        "all_record_digests_match": all(e["source_record_match"] for e in events),
        "all_identity_digests_match": all(e.get("source_identity_match", False) for e in events),
        "fields_used": list(EVALUATION_FIELDS),
        "label_columns_extracted": False,
        "descriptive_summary": summary,
        "assessment": assessment,
        "independent_analyst_study_performed": False,
    }


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", default=DEFAULT_CASE)
    parser.add_argument("--report-dir", type=Path, default=root / "results/milestones/reference-local-test-v1/m7")
    parser.add_argument("--source-root", type=Path, default=root / "data/raw/uwf-zeekdata24/parquet")
    parser.add_argument("--output", type=Path, default=root / "results/chain-witness/revision-report-to-source-v1/walkthrough.json")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    if args.output.exists() and not args.overwrite:
        print(f"refusing to overwrite {args.output}", file=sys.stderr)
        return 2
    result = run(args)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=False) + "\n")
    print(json.dumps({"verdict": result["assessment"]["verdict"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
