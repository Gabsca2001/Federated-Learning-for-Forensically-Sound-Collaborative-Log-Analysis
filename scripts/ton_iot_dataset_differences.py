"""Descriptive Data24 vs ToN-IoT feature-distribution comparison (no training).

Read-only on inputs. Compares the 25 window features between the Data24 reference
snapshot and the ToN-IoT occurrence windows, overall and within comparable label
groups (benign vs benign, attack vs attack, and explicitly mapped ToN-IoT types).
Statistics are descriptive: windows are temporally correlated, so no p-values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np

# Candidate explicit correspondences, stated before looking at any per-subset result.
# Only single-type ToN-IoT windows enter a mapped subset.
EXPLICIT_MAPPING = {
    "scanning": "reconnaissance",
    "password": "credential_access",
}

FEATURE_GROUPS = {
    "volume_counts": [
        "connection_count",
        "originator_bytes_sum",
        "responder_bytes_sum",
        "originator_packets_sum",
        "responder_packets_sum",
    ],
    "ports_destinations": ["unique_destination_count", "unique_destination_port_count"],
    "durations": ["duration_mean", "duration_std", "duration_max"],
    "protocol_fractions": [
        "protocol_tcp_fraction",
        "protocol_udp_fraction",
        "protocol_icmp_fraction",
        "protocol_other_fraction",
    ],
    "service_fractions": [
        "service_dns_fraction",
        "service_http_fraction",
        "service_ssl_fraction",
        "service_ssh_fraction",
        "service_other_fraction",
    ],
    "state_fractions": [
        "state_sf_fraction",
        "state_s0_fraction",
        "state_rej_fraction",
        "state_rsto_fraction",
        "state_rstr_fraction",
        "state_other_fraction",
    ],
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ks_statistic(a: np.ndarray, b: np.ndarray) -> float:
    a = np.sort(a)
    b = np.sort(b)
    grid = np.concatenate([a, b])
    cdf_a = np.searchsorted(a, grid, side="right") / len(a)
    cdf_b = np.searchsorted(b, grid, side="right") / len(b)
    return float(np.max(np.abs(cdf_a - cdf_b)))


def summary(x: np.ndarray) -> dict:
    q = np.quantile(x, [0.05, 0.25, 0.5, 0.75, 0.95])
    return {
        "n": len(x),
        "p05": float(q[0]),
        "p25": float(q[1]),
        "median": float(q[2]),
        "p75": float(q[3]),
        "p95": float(q[4]),
    }


def compare(src: np.ndarray, tgt: np.ndarray, names: list[str], ref: np.ndarray) -> dict:
    """ref: Data24 training matrix that defines the out-of-range envelope."""
    lo = np.quantile(ref, 0.005, axis=0)
    hi = np.quantile(ref, 0.995, axis=0)
    mu = ref.mean(axis=0)
    sd = ref.std(axis=0)
    sd[sd == 0] = 1.0
    out = {}
    for j, name in enumerate(names):
        t = tgt[:, j]
        out[name] = {
            "ks": ks_statistic(src[:, j], t),
            "data24": summary(src[:, j]),
            "ton_iot": summary(t),
            "ton_outside_data24_train_p0.5_p99.5": float(np.mean((t < lo[j]) | (t > hi[j]))),
            "ton_abs_z_gt_5_under_data24_train": float(np.mean(np.abs((t - mu[j]) / sd[j]) > 5)),
        }
    return out


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data24", type=Path, default=root / "artifacts/m2-data24-parquet/dataset.json")
    p.add_argument(
        "--ton-iot",
        type=Path,
        default=Path(
            "/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1"
            "/output/ton-iot-transfer-20261109/windows/occurrence-windows.json"
        ),
    )
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    if a.output.exists():
        raise SystemExit(f"refusing existing output {a.output}")

    d24 = json.loads(a.data24.read_text())
    ton = json.loads(a.ton_iot.read_text())
    names = d24["feature_names"]
    if names != ton["feature_names"]:
        raise SystemExit("feature contracts differ")

    d_rows = d24["rows"]
    t_rows = ton["rows"]
    D = np.array([r["features"] for r in d_rows], dtype=float)
    T = np.array([r["features"] for r in t_rows], dtype=float)
    d_lab = np.array([r["label"] for r in d_rows])
    d_split = np.array([r["split"] for r in d_rows])
    t_lab = np.array([r["label"] for r in t_rows])
    ref = D[d_split == "train"]

    # ToN-IoT source types per window; single-type windows for explicit mapping.
    t_types = [sorted(k for k in r["source_type_counts"] if k != "normal") for r in t_rows]
    t_has_normal = np.array(["normal" in r["source_type_counts"] for r in t_rows])
    single = np.array([len(x) == 1 for x in t_types])
    t_single_type = np.array([x[0] if len(x) == 1 else "" for x in t_types])

    type_window_counts = Counter(x[0] if len(x) == 1 else ("none" if not x else "mixed") for x in t_types)
    pure_type_windows = Counter(
        t_single_type[i] for i in range(len(t_rows)) if single[i] and not t_has_normal[i]
    )

    comparisons = {
        "all_windows": compare(D, T, names, ref),
        "benign_vs_benign": compare(D[d_lab == "benign"], T[t_lab == "benign"], names, ref),
        "attack_vs_attack": compare(D[d_lab != "benign"], T[t_lab != "benign"], names, ref),
    }
    mapped = {}
    for ton_type, d24_label in EXPLICIT_MAPPING.items():
        mask = single & (t_single_type == ton_type)
        n = int(mask.sum())
        mapped[ton_type] = {"data24_label": d24_label, "ton_single_type_windows": n}
        if n >= 5 and (d_lab == d24_label).sum() >= 5:
            comparisons[f"{ton_type}_vs_{d24_label}"] = compare(D[d_lab == d24_label], T[mask], names, ref)

    group_summary = {}
    for cmp_name, cmp in comparisons.items():
        group_summary[cmp_name] = {
            g: {
                "mean_ks": float(np.mean([cmp[f]["ks"] for f in feats])),
                "max_ks_feature": max(feats, key=lambda f: cmp[f]["ks"]),
                "max_ks": float(max(cmp[f]["ks"] for f in feats)),
            }
            for g, feats in FEATURE_GROUPS.items()
        }

    result = {
        "description": "Descriptive Data24 vs ToN-IoT feature-distribution comparison; no training, no p-values.",
        "inputs": {
            "data24": {"path": str(a.data24), "sha256": sha256_file(a.data24), "windows": len(d_rows)},
            "ton_iot": {"path": str(a.ton_iot), "sha256": sha256_file(a.ton_iot), "windows": len(t_rows)},
        },
        "envelope": "Data24 training split (sampled as in the reference snapshot)",
        "data24_label_counts": dict(Counter(d_lab.tolist())),
        "ton_iot_label_counts": dict(Counter(t_lab.tolist())),
        "ton_iot_window_type_composition": dict(type_window_counts),
        "ton_iot_pure_single_type_attack_windows": dict(pure_type_windows),
        "explicit_mapping_declared": EXPLICIT_MAPPING,
        "explicit_mapping_support": mapped,
        "feature_groups": FEATURE_GROUPS,
        "group_summary": group_summary,
        "comparisons": comparisons,
    }
    a.output.mkdir(parents=True)
    (a.output / "dataset-differences.json").write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: result[k] for k in (
        "data24_label_counts", "ton_iot_label_counts", "ton_iot_window_type_composition",
        "ton_iot_pure_single_type_attack_windows", "explicit_mapping_support")}, indent=1))
    for cmp_name, gs in group_summary.items():
        print(cmp_name)
        for g, v in gs.items():
            print(f"  {g:20s} meanKS={v['mean_ks']:.3f} max={v['max_ks']:.3f} ({v['max_ks_feature']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
