# Protocol: does Data24 pre-training reduce the labels needed on ToN-IoT? (v1)

Written 2026-11-10 before any training or evaluation for this study. SHA-256 in
`protocol.sha256`; the script refuses to run if it differs. Not edited after results.

## Question and motivation

Frozen transfer and label-free adaptation did not show that knowledge learned on Data24
transfers (`results/external-data/revision-domain-adaptation-controls-v1`). A pre-trained model can still
be useful if it reaches a given performance on a new network with **fewer labelled
windows** than the same model trained from scratch. This study measures that.

ToN-IoT windows have been examined in earlier studies, so this is an exploratory
assessment on previously observed data, not a blind test; the split and every setting
below are fixed before training.

## Data and split

ToN-IoT occurrence windows (7,934; same file and SHA as the parent studies), 25 features.
Family = `benign` if no attack type, the single attack type otherwise, `mixed` if several.
Within each family, windows are ordered by start time: the first 70% form the **training
pool**, the last 30% the **test set**. Training-pool windows starting less than 3,600 s
before the family's first test window are purged. Binary target: benign vs attack.
Families present in the test are also present in the pool (known-family setting; unseen
family generalization is not assessed here).

Preprocessing, identical for every arm: log1p on the ten count/volume/duration features,
then standardization with mean/std of the **entire training pool without labels**
(std < 1e-9 → 1).

## Label budgets and sampling

Budgets k ∈ {16, 32, 64, 128, 256, 512, all}. For each k and sampling seed
s ∈ {0, 1, 2}, k windows are drawn from the training pool stratified by binary label,
with ⌊k/2⌋ benign and ⌈k/2⌉ attack (capped by availability; "all" uses the whole pool).
The same labelled subset is given to every arm for a given (k, s).

## Arms

Architecture identical to the frozen Data24 model (25→128→64→32 encoder, ReLU), new
binary head (32→2) initialized with the sampling seed.

- **P (pre-trained):** encoder initialized from a Data24 model; three source models —
  the frozen checkpoint `39075d9c…` and the `standard` FedAvg models of seeds 342593 and
  343593 from `artifacts/ton-iot-robust-transfer-v1` (selected rounds 13 and 11). The
  source model index is paired with the sampling seed (s=0 ↔ frozen, s=1 ↔ 342593,
  s=2 ↔ 343593).
- **R (scratch):** encoder randomly initialized with seed 1000 + s.
- **N (novelty reference, no training):** Mahalanobis distance to the benign windows of
  the labelled subset (covariance + 1e-3·I), threshold at the 99th percentile of their
  scores. Uses only the benign labels of the subset.

Training for P and R: full fine-tuning, Adam lr 1e-3, batch size min(32, k), 60 epochs,
class-balanced cross-entropy, no early stopping and no model selection (no validation
labels are assumed). CPU, torch threads = 4, torch seed = sampling seed.

## Metrics (test set)

Balanced accuracy (primary), binary macro-F1, FPR, attack recall, AUROC of P(attack)
(or Mahalanobis score for N). Mean and sample SD over the three seeds per (arm, k).

## Decision rules

Let Δ(k) = mean BA(P) − mean BA(R).

- **Pre-training helps** if Δ(k) ≥ 0.05 for at least two of k ∈ {16, 32, 64} and
  Δ(k) ≥ −0.02 for every k.
- **No benefit** if |Δ(k)| < 0.05 for all of k ∈ {16, 32, 64}.
- **Pre-training hurts** if Δ(k) ≤ −0.05 for at least two of k ∈ {16, 32, 64}.
- **Mixed** otherwise.

Separately reported: the smallest k at which each arm reaches mean BA ≥ 0.80, and whether
P or R exceeds N at each k.

## Limits declared in advance

Known-family setting with within-family chronological split (dates are interleaved across
families); correlated windows; three seeds; the ToN-IoT windows were seen before; a single
target dataset.
