# Protocol: prototype re-anchoring in the Data24 embedding space (v1)

Written 2026-11-10 before computing any embedding score. SHA-256 in `protocol.sha256`;
the script refuses to run if it differs. Not edited after results are seen.

## Question

The Data24 classifier head does not transfer, and novelty detection on raw features
relative to a benign baseline does. In the spirit of prototype-based federated learning
(PROTEAN), is the **encoder representation** learned on Data24 a better space for
baseline-relative detection than the raw 25 features? If so, Data24 training contributes
something transferable even though its decision head does not.

## Targets, baselines and tests (identical to earlier studies)

| Target | Units | Baseline (label-free, assumed normal) | Test |
| --- | --- | --- | --- |
| Data22 | global windows | 2022-01-09 … 2022-01-12 | all other dates |
| ToN-IoT | global windows | 2019-04-02 … 2019-04-03 | all other dates |
| UNSW-NB15 | source-host × minute | S0, 2015-01-22 14:00–16:00 UTC | all S1 (2015-02-18) units |

## Representations

Inputs are standardized with the target baseline mean/std (std < 1e-9 → Data24 training
scale). Embedding = output of the encoder (32-dimensional, after the last ReLU).

- **RAW:** the standardized 25 features (reference; equals the earlier N1-Mahalanobis).
- **EMB-D24:** embeddings from three Data24 encoders — frozen checkpoint `39075d9c…`,
  `standard` seeds 342593 (round 13) and 343593 (round 11). Scores are averaged per
  encoder and results reported per encoder and as the mean over the three.
- **EMB-RAND:** embeddings from three randomly initialized encoders (seeds 0, 1, 2), same
  architecture (control for "any nonlinear projection").

Secondary (reported, not decisive): EMB-D24 with inputs standardized by the Data24
training scaler instead of the target baseline.

## Score and decision rule

Benign prototype = mean of baseline vectors. Primary score: Mahalanobis distance to the
prototype with the baseline covariance + 1e-3·I (embedding) or + 1e-6·I (raw).
Secondary score: Euclidean distance to the prototype. Alert if score > 99th percentile of
baseline scores. Metrics on test: balanced accuracy (primary), FPR, recall, AUROC.

## Decision rules (primary score, EMB-D24 = mean BA over the three Data24 encoders)

Let Δ_raw = BA(EMB-D24) − BA(RAW) and Δ_rand = BA(EMB-D24) − mean BA(EMB-RAND), per target.

- **Data24 embedding helps** if Δ_raw ≥ 0.03 on at least two targets, Δ_raw ≥ −0.02 on all,
  and Δ_rand ≥ 0.03 on at least two targets.
- **Equivalent** if |Δ_raw| < 0.03 on all three targets.
- **Data24 embedding worse** if Δ_raw ≤ −0.03 on at least two targets.
- **Mixed** otherwise.

## Limits declared in advance

Same as the parent studies (period confound on Data22/ToN-IoT; four attack hosts and Argus
mapping on UNSW-NB15; correlated units). Data24 encoders trained on CUDA (two of three).
No few-shot labels are used; prototype re-anchoring is label-free.
