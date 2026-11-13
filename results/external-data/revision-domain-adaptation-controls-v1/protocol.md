# Protocol: controls for the label-free baseline adaptation result (v1)

Written 2026-11-10 before computing any control prediction. SHA-256 in `protocol.sha256`;
the script refuses to run if it differs. Not edited after results are seen.

## Why

`results/revision-domain-adaptation-v1` showed that AB1 (frozen Data24 model, standardization
and alert threshold re-estimated on a benign baseline) meets the predeclared criteria on
Data22 and ToN-IoT. That does **not** yet show that knowledge learned on Data24 transfers:

1. In both datasets attacks occur on dates disjoint from the baseline, so any detector of
   departure from the baseline may score similarly.
2. After baseline standardization, `1 − P(benign)` may only measure distance from the
   baseline.
3. The result rests on one checkpoint.

## Fixed setting (identical to the parent study)

Same datasets, same baseline/test dates (Data22 baseline 2022-01-09…12; ToN-IoT baseline
2019-04-02…03), same baseline standardization (baseline mean/std; std < 1e-9 replaced by the
Data24 training scale), same decision rule: alert if score > 99th percentile of the score on
baseline windows. Test metrics: balanced accuracy (primary), FPR, attack recall, AUROC.

## Compared scorers

**Reference.** `AB1-frozen`: frozen Data24 checkpoint `39075d9c…`, score `1 − P(benign)`.

**N1 – novelty detectors without Data24 knowledge** (fitted on baseline windows only, in
baseline-standardized space):
- `N1-maxz`: max over features of |z|;
- `N1-mahalanobis`: Mahalanobis distance, covariance + 1e-6·I;
- `N1-knn`: mean Euclidean distance to the 5 nearest baseline windows (baseline scores
  computed excluding the window itself);
- `N1-iforest`: Isolation Forest, 200 trees, random_state 0, score = −score_samples.

**N2 – untrained network**: same architecture as the frozen model, random initialization with
seeds 0, 1, 2 (`N2-random-s0/s1/s2`), score `1 − P(benign)`.

**N3 – other Data24 models**: the three `standard` FedAvg models selected on Data24 validation
in `artifacts/ton-iot-robust-transfer-v1` (seeds 341593, 342593, 343593, rounds 11, 13, 11;
trained on CUDA), score `1 − P(benign)`.

## Decision rules (stated before results)

Let Δ_N1 = BA(AB1-frozen) − max BA over the four N1 detectors, and Δ_N2 = BA(AB1-frozen) −
max BA over the three N2 networks, computed per dataset. Taking the best control is
deliberately conservative against the Data24 model.

- **Data24 knowledge contributes** if Δ_N1 ≥ 0.05 **and** Δ_N2 ≥ 0.05 on **both** datasets.
- **Equivalent to novelty detection** if |Δ_N1| < 0.05 on both datasets: the adaptation
  procedure works, but transfer of learned knowledge is not shown.
- **Data24 model worse** if Δ_N1 ≤ −0.05 on both datasets.
- **Mixed** otherwise (reported per dataset).
- **Stability (N3):** the result is model-stable only if all three N3 models meet the parent
  improvement criterion (BA ≥ 0.70 and FPR ≤ 0.30) on both datasets.

All scorers and seeds are reported regardless of outcome.

## Limits declared in advance

Benign and attack windows remain on disjoint dates in both datasets, so no scorer here can
fully exclude a period-change effect; these controls bound it but do not remove it. Single
baseline choice (baseline-length sensitivity is a separate follow-up). Correlated windows,
no significance testing.
