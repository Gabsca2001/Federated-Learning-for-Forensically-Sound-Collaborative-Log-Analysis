"""Frozen Data24 six-class predictions on ToN-IoT subsets with an explicit label correspondence.

Read-only. Reuses the retained frozen-transfer predictions (no new inference).
A window enters a mapped subset when its only non-normal ToN-IoT source type is the
mapped type (normal rows may share the minute). Mappings are declared in
``ton_iot_dataset_differences.EXPLICIT_MAPPING`` before this evaluation.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ton_iot_dataset_differences import EXPLICIT_MAPPING, sha256_file

BASE = Path(
    "/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1"
    "/output/ton-iot-transfer-20261109"
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--windows", type=Path, default=BASE / "windows/occurrence-windows.json")
    p.add_argument("--predictions", type=Path, default=BASE / "occurrence-predictions.json")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    if a.output.exists():
        raise SystemExit(f"refusing existing output {a.output}")

    rows = json.loads(a.windows.read_text())["rows"]
    preds = json.loads(a.predictions.read_text())
    if isinstance(preds, dict):
        preds = preds.get("records") or preds.get("predictions") or preds
    by_id = {r["window_id"]: r for r in preds}
    if len(by_id) != len(rows):
        raise SystemExit(f"prediction count {len(by_id)} != windows {len(rows)}")

    subsets = {}
    for ton_type, d24 in EXPLICIT_MAPPING.items():
        members = []
        for r in rows:
            types = [k for k in r["source_type_counts"] if k != "normal"]
            if types == [ton_type]:
                members.append(r)
        labels = Counter(by_id[r["window_id"]]["predicted_model_label"] for r in members)
        n = len(members)
        subsets[ton_type] = {
            "mapped_data24_label": d24,
            "windows": n,
            "windows_without_normal_rows": sum("normal" not in r["source_type_counts"] for r in members),
            "predicted_label_counts": dict(labels),
            "mapped_label_recall": labels.get(d24, 0) / n if n else None,
            "non_benign_rate": (n - labels.get("benign", 0)) / n if n else None,
        }

    benign = [r for r in rows if r["label"] == "benign"]
    benign_pred = Counter(by_id[r["window_id"]]["predicted_model_label"] for r in benign)
    result = {
        "description": "Frozen Data24 checkpoint on explicitly mapped ToN-IoT subsets; reuses retained predictions.",
        "inputs": {
            "windows": {"path": str(a.windows), "sha256": sha256_file(a.windows)},
            "predictions": {"path": str(a.predictions), "sha256": sha256_file(a.predictions)},
        },
        "explicit_mapping_declared": EXPLICIT_MAPPING,
        "subsets": subsets,
        "benign_windows_predicted_label_counts": dict(benign_pred),
        "caveat": "Benign windows are almost all predicted non-benign, so mapped-label hits must be read against "
        "the benign prediction distribution, not as evidence of tactic recognition.",
    }
    a.output.mkdir(parents=True)
    (a.output / "mapped-subsets.json").write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: result[k] for k in ("subsets", "benign_windows_predicted_label_counts")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
