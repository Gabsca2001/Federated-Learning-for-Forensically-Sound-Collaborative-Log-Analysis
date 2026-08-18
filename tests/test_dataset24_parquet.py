from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from fl_forensics.canonical import sha256_file
from fl_forensics.config import load_yaml
from fl_forensics.dataset24 import audit_dataset, prepare_dataset, verify_workspace
from fl_forensics.dataset24_parquet import PINNED_PARQUET_FILES
from fl_forensics.dataset24_parquet import _flush_consolidated_event


ROOT = Path(__file__).resolve().parents[1]


def _row(*, moment: str, uid: str, tactic: str, technique: str) -> dict[str, object]:
    parsed = datetime.fromisoformat(moment)
    return {
        "community_id": f"community-{uid}",
        "conn_state": "SF",
        "duration": 0.25,
        "history": "ShADadFf",
        "src_ip_zeek": "10.0.0.1",
        "src_port_zeek": 50000,
        "dest_ip_zeek": "10.0.0.2",
        "dest_port_zeek": 443,
        "local_orig": True,
        "local_resp": True,
        "missed_bytes": 0,
        "orig_bytes": 120,
        "orig_ip_bytes": 172,
        "orig_pkts": 2,
        "proto": "tcp",
        "resp_bytes": 240,
        "resp_ip_bytes": 292,
        "resp_pkts": 3,
        "service": "ssl",
        "ts": parsed.timestamp(),
        "uid": uid,
        "datetime": parsed.replace(tzinfo=None),
        "label_tactic": tactic,
        "label_technique": technique,
        "label_binary": "False" if tactic == "none" else "True",
        "label_cve": "none",
    }


def _build_fixture(root: Path) -> tuple[str, tuple[int, str]]:
    import pyarrow as pa
    import pyarrow.parquet as pq

    rows = [
        _row(moment="2024-10-31T10:00:00+00:00", uid="b1", tactic="none", technique="none"),
        _row(moment="2024-10-31T10:02:00+00:00", uid="b1b", tactic="none", technique="none"),
        _row(moment="2024-11-01T10:00:00+00:00", uid="b2", tactic="none", technique="none"),
        _row(moment="2024-11-02T10:00:00+00:00", uid="b3", tactic="none", technique="none"),
        _row(moment="2024-11-03T10:00:00+00:00", uid="b4", tactic="none", technique="none"),
        _row(
            moment="2024-03-01T10:00:00+00:00",
            uid="r1",
            tactic="Reconnaissance",
            technique="T1595",
        ),
        _row(
            moment="2024-03-01T10:02:00+00:00",
            uid="r1b",
            tactic="Reconnaissance",
            technique="T1595",
        ),
        _row(
            moment="2024-03-02T10:00:00+00:00",
            uid="r2",
            tactic="Reconnaissance",
            technique="T1595",
        ),
        _row(
            moment="2024-03-03T10:00:00+00:00",
            uid="r3",
            tactic="Reconnaissance",
            technique="T1595",
        ),
    ]
    shared = _row(
        moment="2024-03-01T11:00:00+00:00",
        uid="shared",
        tactic="Defense Evasion",
        technique="T1078",
    )
    rows.append(shared)
    duplicate = dict(shared)
    duplicate["label_tactic"] = "Persistence"
    duplicate["label_technique"] = "Duplicate"
    rows.append(duplicate)

    relative_path = "fixture/week.snappy.parquet"
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows), path)
    pinned = (path.stat().st_size, sha256_file(path))
    manifest = {
        "schema_version": "1.0",
        "dataset": "UWF-ZeekData24",
        "source_format": "parquet",
        "source_release": "test-fixture",
        "controlled_ingestion_at": datetime(2026, 8, 18, tzinfo=UTC).isoformat(),
        "files": [
            {
                "capture_period": "fixture",
                "relative_path": relative_path,
                "source_url": "https://datasets.uwf.edu/test/week.snappy.parquet",
                "size_bytes": pinned[0],
                "sha256": pinned[1],
            }
        ],
    }
    (root / "download_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return relative_path, pinned


@unittest.skipUnless(
    importlib.util.find_spec("pyarrow"),
    "optional PyArrow dependency is not installed",
)
class Dataset24ParquetTests(unittest.TestCase):
    def test_primary_tactic_is_not_erased_by_duplicate_taxonomy_rows(self) -> None:
        source = _row(
            moment="2024-03-01T12:00:00+00:00",
            uid="exfil",
            tactic="Exfiltration",
            technique="T1041",
        )
        normalized = {key: str(value) for key, value in source.items()}
        record = _flush_consolidated_event(
            identity="a" * 64,
            row=normalized,
            tactics={
                "defense_evasion",
                "exfiltration",
                "initial_access",
                "persistence",
                "privilege_escalation",
            },
            primary_tactics={"defense_evasion", "exfiltration"},
            techniques={"T1041"},
            sources=[],
            batch_id="fixture",
            batch_digest="b" * 64,
        )
        event = json.loads(record[5])
        self.assertEqual(event["label"], "exfiltration")
        self.assertEqual(
            event["primary_tactics"], ["defense_evasion", "exfiltration"]
        )

    def test_parquet_prepare_is_deterministic_and_samples_training_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            relative_path, pinned = _build_fixture(source)
            config, _digest = load_yaml(ROOT / "configs" / "base.yaml")
            preprocessing = copy.deepcopy(config["preprocessing"])
            preprocessing["training_sampling"] = {
                "enabled": True,
                "method": "deterministic-hash-ranking-within-class",
                "seed": 341593,
                "majority_labels": ["benign", "reconnaissance"],
                "majority_fraction": "0.5",
                "minority_fraction": "1.0",
            }
            frozen = {relative_path: pinned}
            with patch.dict(PINNED_PARQUET_FILES, frozen, clear=True):
                audit = audit_dataset(source)
                self.assertEqual(audit["source_format"], "parquet")
                self.assertEqual(audit["row_count"], 11)
                self.assertEqual(audit["unique_connection_identity_count"], 10)
                self.assertEqual(audit["cross_label_identity_count"], 1)

                first = prepare_dataset(
                    source_root=source,
                    output=root / "first",
                    preprocessing_config=preprocessing,
                )
                second = prepare_dataset(
                    source_root=source,
                    output=root / "second",
                    preprocessing_config=preprocessing,
                )

            self.assertEqual(first["dataset_sha256"], second["dataset_sha256"])
            self.assertEqual(first["unique_event_count"], 10)
            self.assertEqual(verify_workspace(root / "first")["status"], "verified")
            sampling = json.loads(
                (root / "first" / "training_sampling.json").read_text()
            )
            self.assertTrue(sampling["enabled"])
            self.assertLess(
                sampling["training_window_count_after"],
                sampling["training_window_count_before"],
            )
            manifest = json.loads((root / "first" / "manifest.json").read_text())
            before = manifest["split_counts_before_training_sampling"]
            after = manifest["split_counts"]
            for split in ("validation", "test", "temporal_holdout"):
                self.assertEqual(before[split], after[split])


if __name__ == "__main__":
    unittest.main()
