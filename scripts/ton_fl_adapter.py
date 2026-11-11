"""ToN-IoT adapter for the federated gate engine (binary benign/attack).

Source: verified host/minute windows (`host-windows.npz`, 80,172 windows, the
same 25 aggregate features as Data24), produced by revision-ton-iot-host-windows-v1.
The file is copied (4 MB) into the study and pinned by SHA-256.

* Chronological split by UTC minute bucket, reproducing the published support:
  train <= 27 Apr 2019 22:59 (boundary hour purged), validation 28 Apr 00:00-22:59,
  test 29 Apr. Counts are checked against the published preparation summary.
* Training windows are split once (seeded, stratified by label) into a disjoint
  WARM-START portion (only used to train the starting model) and an FL POOL. The FL
  pool is subsampled, stratified, to a declared size to bound compute.
* Standard scaler fitted on all training windows only; validation/test never fit.
* Rows use the engine schema {capture_id, features, label, window_id}; labels
  'attack'/'benign' (sorted class order). Balanced class weights from the FL pool.
* Starting model: frozen M3 MLP shape with a 2-way head, trained centrally on the
  warm-start portion with a fixed seed; validation metrics recorded.

Usage: ton_fl_adapter.py prepare --out DIR --source NPZ [--fl-pool N]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
PUBLISHED = ROOT / 'results/revision-ton-iot-host-windows-v1/windows/preparation-summary.json'
SOURCE_SHA256 = 'd2fd4135fd5f18dfd1eb3277291750aa3f2bc0e160a22e87ca8e5699590706b4'
CLASSES = ['attack', 'benign']
SPLIT_SEED = 2027100001
ARCH = dict(input_features=25, class_count=2, hidden_layers=[128, 64], embedding_size=32, dropout=0.0)
WARM = dict(fraction=0.15, epochs=10, batch_size=128, learning_rate=0.001, seed=2027100002)


def sha(path):
    h = hashlib.sha256(); h.update(Path(path).read_bytes()); return h.hexdigest()


def minute(y, m, d, hh=0):
    return int(datetime(y, m, d, hh, tzinfo=timezone.utc).timestamp() // 60)


DURATION_MAX = 5  # feature index of duration_max (seconds), raw scale


def split_of(bucket, X):
    """Corrected chronological assignment (revision-ton-iot-flow-end-v2).

    A validation minute is eligible only if window_end + global-minute duration_max
    + 1 s does not pass the embargo start (28 Apr 23:00 UTC); the global-minute
    duration_max is the maximum over its host windows (exact reconstruction).
    """
    b = np.asarray(bucket)
    train = b < minute(2019, 4, 27, 23)
    in_val = (b >= minute(2019, 4, 28)) & (b < minute(2019, 4, 28, 23))
    embargo = minute(2019, 4, 28, 23) * 60
    gmax = {}
    for i in np.where(in_val)[0]:
        gmax[int(b[i])] = max(gmax.get(int(b[i]), 0.0), float(X[i, DURATION_MAX]))
    eligible = {m for m, d in gmax.items() if (m + 1) * 60 + d + 1 <= embargo}
    val = in_val & np.isin(b, list(eligible))
    test = (b >= minute(2019, 4, 29)) & (b < minute(2019, 4, 30))
    return train, val, test


def rows_for(idx, X, y, bucket, host):
    out = []
    for i in idx:
        day = datetime.fromtimestamp(int(bucket[i]) * 60, tz=timezone.utc).strftime('%Y-%m-%d')
        wid = hashlib.sha256(f'{host[i]}|{int(bucket[i])}'.encode()).hexdigest()[:24]
        out.append(dict(capture_id=day, features=[float(v) for v in X[i]], label=CLASSES[1] if y[i] == 0 else CLASSES[0],
                        window_id=f'ton-host-{wid}'))
    return out


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f'refusing to overwrite {path}')
    path.write_text(json.dumps(obj, sort_keys=True, separators=(',', ':')))
    return sha(path)


def train_warm_start(rows, val_rows, out_dir):
    from fl_forensics.federated_model import dependencies, build_model, train_local, export_state, architecture_record, evaluate_rows, seed_everything
    deps = dependencies(); np_dep, torch = deps[0], deps[1]
    torch.set_num_threads(1); torch.use_deterministic_algorithms(True)
    seed_everything(WARM['seed'], torch=torch, np=np_dep)
    model = build_model(input_features=ARCH['input_features'], class_count=ARCH['class_count'], hidden_layers=ARCH['hidden_layers'],
                        embedding_size=ARCH['embedding_size'], dropout=ARCH['dropout'], torch=torch)
    counts = {c: sum(r['label'] == c for r in rows) for c in CLASSES}
    weights = {c: len(rows) / (len(CLASSES) * counts[c]) for c in CLASSES}
    train_local(model=model, rows=rows, class_names=CLASSES, class_weights=weights, epochs=WARM['epochs'],
                batch_size=WARM['batch_size'], learning_rate=WARM['learning_rate'], seed=WARM['seed'], device_name='cpu',
                torch=torch, np=np_dep)
    arch = architecture_record(input_features=ARCH['input_features'], class_count=ARCH['class_count'],
                               hidden_layers=ARCH['hidden_layers'], embedding_size=ARCH['embedding_size'], dropout=ARCH['dropout'])
    exported = export_state(model, architecture=arch, class_names=CLASSES)
    path = out_dir / 'base-model.json'
    digest = write(path, exported)
    m = evaluate_rows(model=model, rows=val_rows, class_names=CLASSES, batch_size=1024, torch=torch, np=np_dep,
                      accuracy_score=deps[5], confusion_matrix=deps[6], precision_recall_fscore_support=deps[7])
    metrics = {k: m[k] for k in ('accuracy', 'macro_f1_all_model_classes', 'per_class', 'confusion_matrix') if k in m}
    return digest, weights, metrics


def prepare(out, source, fl_pool):
    out = Path(out)
    if out.exists():
        raise SystemExit('refusing to overwrite an existing ToN study directory')
    if sha(source) != SOURCE_SHA256:
        raise SystemExit('source npz digest mismatch')
    out.mkdir(parents=True)
    (out / 'source').mkdir(); shutil.copyfile(source, out / 'source/host-windows.npz')
    z = np.load(out / 'source/host-windows.npz', allow_pickle=False)
    X, y, bucket, host = z['features'], z['actual'].astype(int), z['bucket'], z['host']
    tr, va, te = split_of(bucket, X)
    published = json.loads(PUBLISHED.read_text())['split_support']
    observed = {k: dict(host_windows=int(m.sum()), benign=int(((y == 0) & m).sum()), attack=int(((y == 1) & m).sum()))
                for k, m in (('train', tr), ('validation', va), ('test', te))}
    for k in observed:
        exp = published[k]
        if (observed[k]['host_windows'], observed[k]['benign'], observed[k]['attack']) != (exp['host_windows'], exp['binary_counts']['benign'], exp['binary_counts']['attack']):
            raise SystemExit(f'split {k} does not reproduce the published support: {observed[k]} vs {exp}')
    rng = np.random.default_rng(SPLIT_SEED)
    train_idx = np.where(tr)[0]; warm, pool = [], []
    for label in (0, 1):
        idx = train_idx[y[train_idx] == label]; idx = idx[rng.permutation(len(idx))]
        k = int(round(WARM['fraction'] * len(idx))); warm += idx[:k].tolist(); pool += idx[k:].tolist()
    pool = np.array(sorted(pool))
    if fl_pool and fl_pool < len(pool):
        keep = []
        for label in (0, 1):
            idx = pool[y[pool] == label]; n = int(round(fl_pool * len(idx) / len(pool)))
            keep += idx[rng.permutation(len(idx))[:n]].tolist()
        pool = np.array(sorted(keep))
    mu = X[train_idx].mean(axis=0); sd = X[train_idx].std(axis=0); sd[sd == 0] = 1.0
    Xs = (X - mu) / sd
    warm_rows = rows_for(sorted(warm), Xs, y, bucket, host)
    pool_rows = rows_for(pool.tolist(), Xs, y, bucket, host)
    val_rows = rows_for(np.where(va)[0].tolist(), Xs, y, bucket, host)
    test_rows = rows_for(np.where(te)[0].tolist(), Xs, y, bucket, host)
    ids = [r['window_id'] for r in warm_rows + pool_rows + val_rows + test_rows]
    if len(ids) != len(set(ids)):
        raise SystemExit('window_id collision')
    pins = dict(
        warm_start=write(out / 'data/warm-start.json', dict(rows={'train': warm_rows}, class_names=CLASSES)),
        fl_pool=write(out / 'data/fl-pool.json', dict(rows={'train': pool_rows}, class_names=CLASSES)),
        validation=write(out / 'data/validation.json', dict(rows={'validation': val_rows}, class_names=CLASSES)),
        test=write(out / 'data/test.json', dict(rows={'test': test_rows}, class_names=CLASSES)),
        scaler=write(out / 'data/scaler.json', dict(mean=mu.tolist(), std=sd.tolist(), fit='all chronological training windows')))
    base_sha, warm_weights, warm_metrics = train_warm_start(warm_rows, val_rows, out)
    counts = {c: sum(r['label'] == c for r in pool_rows) for c in CLASSES}
    class_weights = {c: len(pool_rows) / (len(CLASSES) * counts[c]) for c in CLASSES}
    manifest = dict(profile='ton-fl-gate-data-v1', source=dict(path='source/host-windows.npz', sha256=SOURCE_SHA256,
                    producer='revision-ton-iot-host-windows-v1'), split_support=observed, split_reproduces_published=True,
                    warm_start=dict(windows=len(warm_rows), **WARM), fl_pool=dict(windows=len(pool_rows), class_counts=counts,
                    requested=fl_pool), validation_windows=len(val_rows), test_windows=len(test_rows), class_names=CLASSES,
                    global_class_weights=class_weights, pins=pins, base_model_sha256=base_sha, architecture=ARCH,
                    warm_start_validation=warm_metrics, split_seed=SPLIT_SEED,
                    note='validation/test windows are never used for fitting; scaler fitted on training windows only')
    write(out / 'data/manifest.json', manifest)
    print(json.dumps({k: manifest[k] for k in ('split_support', 'fl_pool', 'validation_windows', 'test_windows', 'global_class_weights')}, indent=1))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=('prepare',)); ap.add_argument('--out', required=True); ap.add_argument('--source', required=True)
    ap.add_argument('--fl-pool', type=int, default=15000)
    a = ap.parse_args(); prepare(a.out, a.source, a.fl_pool)


if __name__ == '__main__':
    main()
