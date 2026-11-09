# Protocol: Data24-selected robust preprocessing for frozen transfer to ToN-IoT (v1)

Frozen before any training for this study and before any ToN-IoT inference.
Its SHA-256 is stored in `protocol.sha256`. The script refuses to run if the
digest differs. This file is not edited after ToN-IoT results are seen.

## 0. Question and baseline

Question: does a preprocessing that is less sensitive to feature scale, selected
**only** on Data24 validation, improve frozen (no ToN-IoT fitting) transfer to the
ToN-IoT network windows?

Frozen baseline (`results/revision-ton-iot-transfer-v1/transfer-results.json`,
model `39075d9c…`, round 11, scaler `70b0471a…`, occurrence view, 7 934 windows):
- balanced accuracy 0.5013
- FPR 0.9972
- AUROC 0.8935
- confusion [[8, 2880], [1, 5045]] (rows: true benign/attack; columns: predicted benign/attack)

## 1. Inputs (all pre-existing; nothing rebuilt)

- Data24 M2 dataset and scaler: `artifacts/m2-data24-parquet` (`scaler.json`
  `70b0471a…`, fitted on the Data24 training split only).
- Data24 FL partition: `artifacts/m3-data24-parquet-iid-local-test-v1`
  (manifest `6eea1dee…`, 15 IID clients, class weights `global_class_weights`),
  the same partition as the frozen reference campaign.
- Configuration: `configs/federation.yaml`.
- ToN-IoT windows (opened only in the evaluation phase):
  `OUT/ton-iot-transfer-20261109/windows/occurrence-windows.json`
  (SHA-256 `57ebec4e…c2c`, primary view) and `exact-projection-windows.json`
  (SHA-256 `97b4da80…605c`, duplicate-sensitivity view). `OUT` =
  `/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output`.

## 2. Variants

### 2a. Preprocessing variants (eligible for selection)

These are exactly `VARIANTS` from `scripts/revision_generalization.py`, fitted with
its `fit_variant` (Data24 train only; the standard path reuses the frozen
training scaler):

1. `standard`: all 25 features, z-score with the frozen Data24 training scaler.
2. `log1p`: log1p on the 10 heavy-tailed count/volume/duration features, then z-score.
3. `log1p-winsor`: log1p, then clipping at the Data24-training 0.1%/99.9%
   quantiles (heavy-tailed features only), then z-score.
4. `proportions-only`: the 15 fraction features only, standard.
5. `counts-only`: the 10 count/volume/duration features only, log1p.
6. `standard-group-balanced`: as `standard`, with block factors
   sqrt(25/(2·10)) for counts and sqrt(25/(2·15)) for fractions.
7. `log1p-winsor-group-balanced`: as `log1p-winsor`, with the same block factors.

### 2b. Feature-group ablations (diagnostic only, NOT eligible for selection)

Each ablation starts from `standard` (the frozen Data24 training scaler restricted to
the remaining columns) and removes one group:

| Ablation | Removed features (real names) | Remaining |
|---|---|---|
| `ablate-ports-destinations` | `unique_destination_count`, `unique_destination_port_count` | 23 |
| `ablate-connection-states` | `state_sf_fraction`, `state_s0_fraction`, `state_rej_fraction`, `state_rsto_fraction`, `state_rstr_fraction`, `state_other_fraction` | 19 |
| `ablate-byte-packet-volumes` | `originator_bytes_sum`, `responder_bytes_sum`, `originator_packets_sum`, `responder_packets_sum` | 21 |
| `ablate-durations` | `duration_mean`, `duration_std`, `duration_max` | 22 |

`connection_count`, the 4 `protocol_*` and the 5 `service_*` fractions are never
removed.

## 3. Training (identical for every variant)

- Same architecture and FedAvg protocol as the reference, from
  `configs/federation.yaml`:
  - MLP with hidden layers [128, 64], embedding 32, dropout 0.0, ReLU, 6 classes;
  - FedAvg over all 15 clients each round, 30 rounds, 2 local epochs, batch 128;
  - Adam with learning rate 0.001, global class weights from the partition.
- Implementation: `fl_forensics.retraining_replay.create_retraining_replay` (the
  same controlled FedAvg replay used by `scripts/revision_federated_generalization.py`).
  The input dimension equals the variant's feature count, and features are
  rounded to 12 decimals before float32.
- This is a controlled replay. It is not the attested/secure campaign, and it is
  not expected to reproduce the `39075d9c…` bytes. Whether `standard` with seed
  341593 reproduces that hash is reported descriptively.
- Seeds: 341593, 342593, 343593 (the `SEEDS` of the reference scripts).
- Round selection per run: maximum Data24 validation `macro_f1_all_model_classes`,
  with the earliest round winning ties.
- Transforms and scalers are fitted on the Data24 training split only. Data24
  validation is used for round selection and variant selection. The Data24 test
  split is not used.

## 4. Variant selection (Data24 validation only)

- Metric: for each eligible variant, the mean over the 3 seeds of the Data24
  validation `macro_f1_all_model_classes` at each run's selected round.
- Tie-break: exact ties go to the earlier variant in the order of §2a.
- Ablations are not eligible.
- The selection is written to `selection-before-ton-iot.json` together with its
  SHA-256 (`selection-before-ton-iot.sha256`) before any ToN-IoT file is opened.
  The evaluation phase runs as a separate process, checks both digests, and
  refuses to run otherwise.
- Caveat: the same validation split selects rounds and variants, so the
  selection metric is optimistic in the same way for every variant.

## 5. ToN-IoT evaluation (after selection is frozen)

- Applied to every variant and every seed (11 × 3 = 33 models), not only the
  selected one.
- Decision rule: argmax over the 6 classes, collapsed to benign vs. attack (no
  new threshold).
- Score: 1 − P(benign), used for the threshold-free AUROC and AP.
- Metrics:
  - balanced accuracy, FPR, attack recall, attack precision;
  - binary macro-F1 (mean of the benign-F1 and attack-F1);
  - AUROC and AP;
  - confusion matrix.
- Reported per seed and as the mean ± sample SD over the 3 seeds.
- Primary view: occurrence windows. The exact-projection view is reported
  unconditionally as sensitivity and is never used to choose anything.

## 6. Decision criteria (descriptive, not calibrated)

The **selected** variant is judged against the frozen baseline (BA 0.5013,
FPR 0.9972) on the primary view.

**Improvement** requires all of the following:
- I1. Mean balanced accuracy is at least 0.60.
- I2. Every one of the 3 seeds has balanced accuracy above 0.5013 and FPR below
  0.9972.
- I3. Mean attack recall is at least 0.50, so the gain does not come from a
  near-constant benign prediction.
- I4. Attribution to preprocessing: if the selected variant is not `standard`,
  its balanced accuracy exceeds the `standard` replay's for each seed (paired by
  seed). Without I4, an I1–I3 pass is reported as "improvement over the frozen
  checkpoint, not attributable to preprocessing".

**Negative** if any of the following holds:
- N1. Mean balanced accuracy is at most 0.55.
- N2. Mean FPR is at least 0.95.
- N3. The selected variant is `standard`. Data24-only selection then does not
  choose a scale-robust preprocessing, so the answer to the question is
  negative. The other variants' ToN-IoT numbers are still reported, as
  exploratory results.

**Inconclusive**: none of the above sets is satisfied in full. For example:
- mean balanced accuracy is between 0.55 and 0.60;
- the seeds disagree in direction;
- I1–I3 hold but I4 fails.

AUROC and AP are secondary. A change in AUROC without a change in the argmax
decision is reported but does not count as improvement.

**Ablation reading**: for each ablation, report the mean change (ablation − `standard`
replay, paired by seed) in FPR and AUROC. The group with the largest absolute
mean change is named for each metric. This is descriptive and makes no
significance claim.

## 7. Limits declared in advance

- There is one source dataset (Data24) and one target (ToN-IoT network windows).
- The 7 934 one-minute windows from 10 capture dates are correlated and are not
  independent trials.
- There are only 3 seeds. No confidence intervals or hypothesis tests are
  claimed.
- The feature mapping between Zeek Data24 and ToN-IoT columns is as built by the
  existing window code. Label semantics differ: ToN-IoT attack types are not
  mapped to Data24 tactics.
- Prior exposure: before writing this protocol I had seen the frozen baseline
  numbers above, the ToN-IoT window schema (field names only), and parts of
  `results/revision-ton-iot-benign-robustness-v1/README.md`. The latter compares
  representations for models trained **on ToN-IoT**, a different setup from this
  frozen transfer. I had seen no transfer results for any of the variants above.
