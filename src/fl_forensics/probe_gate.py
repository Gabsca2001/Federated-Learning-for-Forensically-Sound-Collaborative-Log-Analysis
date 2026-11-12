"""Behavioural trigger probe: per-key client gate and global-model drift.

Pure functions, ported unchanged from the research gates confirmed live
(scripts/trigger_probe_gate.py, scripts/keynorm_probe_gate.py, and the global rule of
scripts/revision_global_probe_study.py; results/revision-probe-keynorm-confirm,
results/revision-global-probe-confirm). For each key k = (feature j, value v), the server's clean
validation attack rows are copied with feature j set to v standard units; shortcut_k is the
increase in the fraction predicted as the benign class.

* Client gate: excess_k = shortcut_k - round peer median_k; score = max_k excess_k / s_k with
  s_k = max(clean maximum excess_k, floor); quarantine when score > multiplier.
* Global drift: drift_k = shortcut_k(candidate aggregate) - shortcut_k(campaign initial model);
  score = max_k drift_k / max(clean maximum drift_k, floor); roll back when score > multiplier.
"""

from __future__ import annotations

from typing import Any

import numpy as np

VALUES = (3.0, 6.0, 12.0)

Key = tuple[int, float]


def probe_inputs(validation_rows: list[dict[str, Any]], benign_label: str = "benign"):
    x = np.array(
        [r["features"] for r in validation_rows if r["label"] != benign_label], dtype=np.float32
    )
    if len(x) == 0 or x.ndim != 2:
        raise ValueError("no attack rows in the validation split")
    blocks, keys = [x], [None]
    for j in range(x.shape[1]):
        for v in VALUES:
            y = x.copy()
            y[:, j] = v
            blocks.append(y)
            keys.append((j, v))
    return np.concatenate(blocks), keys, len(x)


def shortcuts(model: Any, stacked: Any, keys: list, n: int, benign_index: int, torch: Any) -> dict[Key, float]:
    model.eval()
    with torch.no_grad():
        pred = model(torch.from_numpy(stacked)).argmax(dim=1).numpy().reshape(len(keys), n)
    rates = (pred == benign_index).mean(axis=1)
    return {k: float(rates[i] - rates[0]) for i, k in enumerate(keys) if k is not None}


def scale_table(rows: list[list[float]], floor: float) -> dict[Key, float]:
    return {(int(j), float(v)): max(float(s), floor) for j, v, s in rows}


def client_scores(per_client: dict[str, dict[Key, float]], scales: dict[Key, float]) -> dict[str, tuple[float, list]]:
    clients = sorted(per_client)
    keys = list(per_client[clients[0]])
    if any(list(per_client[c]) != keys for c in clients) or set(keys) != set(scales):
        raise ValueError("probe key mismatch")
    med = {k: float(np.median([per_client[c][k] for c in clients])) for k in keys}
    out = {}
    for c in clients:
        z = {k: (per_client[c][k] - med[k]) / scales[k] for k in keys}
        best = max(keys, key=z.get)
        out[c] = (float(z[best]), [int(best[0]), float(best[1])])
    return out


def drift_score(candidate: dict[Key, float], initial: dict[Key, float], scales: dict[Key, float]) -> tuple[float, list]:
    if set(candidate) != set(scales) or set(initial) != set(scales):
        raise ValueError("global probe key mismatch")
    z = {k: (candidate[k] - initial[k]) / scales[k] for k in scales}
    best = max(z, key=z.get)
    return float(z[best]), [int(best[0]), float(best[1])]
