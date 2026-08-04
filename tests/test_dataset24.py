from __future__ import annotations

import csv
import importlib.util
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from fl_forensics.canonical import sha256_file
from fl_forensics.central_baseline import train_central_baseline, verify_central_baseline
from fl_forensics.config import load_yaml
from fl_forensics.dataset24 import (
    EXPECTED_COLUMNS,
    audit_dataset,
    prepare_dataset,
    verify_workspace,
)

ROOT = Path(__file__).resolve().parents[1]


def _row(*, moment: str, uid: str, tactic: str, technique: str) -> dict[str, str]:
    parsed = datetime.fromisoformat(moment)
    return {
        "community_id": f"community-{uid}",
        "conn_state": "SF",
        "duration": "0.25",
        "history": "ShADadFf",
        "src_ip_zeek": "10.0.0.1",
        "src_port_zeek": "50000",
        "dest_ip_zeek": "10.0.0.2",
        "dest_port_zeek": "443",
        "local_orig": "true",
        "local_resp": "true",
        "missed_bytes": "0",
        "orig_bytes": "120",
        "orig_ip_bytes": "172",
        "orig_pkts": "2",
        "proto": "tcp",
        "resp_bytes": "240",
        "resp_ip_bytes": "292",
        "resp_pkts": "3",
        "service": "ssl",
        "ts": str(parsed.timestamp()),
        "uid": uid,
        "datetime": moment,
        "label_tactic": tactic,
        "label_technique": technique,
        "label_binary": "False" if tactic == "none" else "True",
        "label_cve": "none",
    }


def _write_partition(root: Path, label: str, rows: list[dict[str, str]]) -> Path:
    path = root / label / f"{label.lower()}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=EXPECTED_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return path


def _build_fixture(root: Path) -> None:
    paths = [
        _write_partition(
            root,
            "Benign",
            [
                _row(moment="2024-10-31T10:00:00Z", uid="b1", tactic="none", technique="none"),
                _row(moment="2024-11-01T10:00:00Z", uid="b2", tactic="none", technique="none"),
                _row(moment="2024-11-02T10:00:00Z", uid="b3", tactic="none", technique="none"),
                _row(moment="2024-11-03T10:00:00Z", uid="b4", tactic="none", technique="none"),
            ],
        ),
        _write_partition(
            root,
            "Reconnaissance",
            [
                _row(
                    moment="2024-03-01T10:00:00Z",
                    uid="r1",
                    tactic="Reconnaissance",
                    technique="T1595",
                ),
                _row(
                    moment="2024-03-02T10:00:00Z",
                    uid="r2",
                    tactic="Reconnaissance",
                    technique="T1595",
                ),
                _row(
                    moment="2024-03-03T10:00:00Z",
                    uid="r3",
                    tactic="Reconnaissance",
                    technique="T1595",
                ),
            ],
        ),
    ]
    shared = _row(
        moment="2024-03-01T11:00:00Z",
        uid="shared",
        tactic="Defense Evasion",
        technique="T1078",
    )
    paths.append(_write_partition(root, "Defense_Evasion", [shared]))
    duplicate = dict(shared)
    duplicate["label_tactic"] = "Persistence"
    duplicate["label_technique"] = "Duplicate"
    paths.append(_write_partition(root, "Persistence", [duplicate]))

    manifest = {
        "schema_version": "1.0",
        "dataset": "UWF-ZeekData24",
        "controlled_ingestion_at": datetime(2026, 8, 4, tzinfo=UTC).isoformat(),
        "files": [
            {
                "label": path.parent.name,
                "relative_path": path.relative_to(root).as_posix(),
                "source_url": f"https://datasets.uwf.edu/test/{path.name}",
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in sorted(paths)
        ],
    }
    (root / "download_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


class Dataset24Tests(unittest.TestCase):
    def test_audit_surfaces_temporal_and_cross_label_risks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            _build_fixture(source)
            audit = audit_dataset(source)
            self.assertEqual(audit["dataset"], "UWF-ZeekData24")
            self.assertEqual(audit["row_count"], 9)
            self.assertEqual(audit["unique_connection_identity_count"], 8)
            self.assertEqual(audit["cross_label_identity_count"], 1)
            risks = {item["id"]: item["present"] for item in audit["leakage_and_quality_risks"]}
            self.assertTrue(risks["R-DATA24-TIME-LABEL"])
            self.assertTrue(risks["R-DATA24-CROSS-LABEL"])

    def test_prepare_is_deterministic_and_group_disjoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            _build_fixture(source)
            config, _digest = load_yaml(ROOT / "configs" / "base.yaml")
            first = prepare_dataset(
                source_root=source,
                output=root / "first",
                preprocessing_config=config["preprocessing"],
            )
            second = prepare_dataset(
                source_root=source,
                output=root / "second",
                preprocessing_config=config["preprocessing"],
            )
            self.assertEqual(first["dataset_sha256"], second["dataset_sha256"])
            self.assertEqual(first["unique_event_count"], 8)
            self.assertEqual(verify_workspace(root / "first")["status"], "verified")
            split = json.loads((root / "first" / "split_manifest.json").read_text())
            groups = {name: set(values) for name, values in split["groups"].items()}
            self.assertEqual(groups["temporal_holdout"], {"2024-11-03"})
            names = sorted(groups)
            for index, name in enumerate(names):
                for other in names[index + 1 :]:
                    self.assertFalse(groups[name] & groups[other])
            scaler = json.loads((root / "first" / "scaler.json").read_text())
            self.assertEqual(scaler["fitted_on_split"], "train")
            self.assertEqual(
                scaler["training_row_count"], first["split_counts"]["train"]
            )

    @unittest.skipUnless(
        importlib.util.find_spec("numpy") and importlib.util.find_spec("sklearn"),
        "optional M2 numerical dependencies are not installed",
    )
    def test_central_baseline_is_linked_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            _build_fixture(source)
            config, _digest = load_yaml(ROOT / "configs" / "base.yaml")
            dataset_workspace = root / "dataset"
            prepare_dataset(
                source_root=source,
                output=dataset_workspace,
                preprocessing_config=config["preprocessing"],
            )
            baseline_workspace = root / "baseline"
            result = train_central_baseline(
                workspace=dataset_workspace,
                output=baseline_workspace,
                config_path=ROOT / "configs" / "base.yaml",
            )
            self.assertEqual(result["status"], "trained")
            verification = verify_central_baseline(
                workspace=baseline_workspace,
                dataset_workspace=dataset_workspace,
            )
            self.assertEqual(verification["status"], "verified")


if __name__ == "__main__":
    unittest.main()
