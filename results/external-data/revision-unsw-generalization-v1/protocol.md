# Protocol: Data24 generalization tests on UNSW-NB15 (v1)

Written 2026-11-10 before any model prediction on UNSW-NB15. SHA-256 in `protocol.sha256`;
the script refuses to run if it differs. Not edited after results are seen.

## Question

On Data22 and ToN-IoT, benign and attack traffic lie in different periods, so detectors of
departure from a baseline period could not be separated from attack recognition. UNSW-NB15
source-host × minute units place benign and attack units **in the same minutes** (all 805
attack minutes also contain benign units). Here we ask, on that cleaner setting:

1. Does the frozen Data24 model transfer, with or without label-free baseline adaptation?
2. Does Data24 knowledge beat novelty detectors that know nothing about Data24?
3. Does Data24 pre-training reduce the labels needed on UNSW-NB15?

## Data

`artifacts/unsw-nb15-host-units-v1/units.json` (SHA-256 `29d946b8…`): 27,076 units, 25
features, approved Argus→Zeek state mapping (`results/revision-unsw-nb15-preflight-v1`).
Sessions: S0 = 2015-01-22/23, S1 = 2015-02-18. Global windows
(`artifacts/unsw-nb15-windows-v1/windows.json`) are evaluated as a secondary view only.

## Splits (fixed)

- **Baseline (label-free, assumed normal):** S0 units with start time in
  [2015-01-22 14:00, 16:00) UTC. Released labels in this interval are recorded as a check.
- **Test:** all S1 units. Secondary test views: (i) S1 units in minutes that contain at
  least one attack unit ("same-minute view"); (ii) S1 units of the four attack source hosts
  only ("attacker-host view": their benign vs attack minutes).
- **Label-efficiency pool:** all S0 units (labels used); test = all S1 units.

## Part 1 – transfer and adaptation (inference only)

Same scorers and rules as the domain-adaptation studies: `C0` (Data24 scaler, six-class
argmax collapsed), `AB1-frozen` (baseline standardization + `1 − P(benign)` above the
99th baseline percentile), N1 detectors (max |z|, Mahalanobis, kNN k=5, Isolation Forest
200 trees, random_state 0) fitted on baseline units, N2 random networks (seeds 0, 1, 2),
N3 Data24 `standard` models (seeds 341593, 342593, 343593). Baseline std < 1e-9 → Data24
training scale. Metrics on test: balanced accuracy (primary), FPR, attack recall, AUROC.

Decision rules (per test view "all S1"):
- **Data24 knowledge contributes** if BA(AB1-frozen) − max BA(N1) ≥ 0.05 and
  BA(AB1-frozen) − max BA(N2) ≥ 0.05.
- **Equivalent to novelty detection** if |BA(AB1-frozen) − max BA(N1)| < 0.05.
- **Data24 model worse** if BA(AB1-frozen) − max BA(N1) ≤ −0.05.
- **N3 stability:** all three N3 models within 0.05 BA of AB1-frozen.

Sensitivity (reported, not decisive): the same comparison with the six state features
neutralized (set to their baseline mean before scoring), to bound the effect of the
Argus→Zeek state mapping.

## Part 2 – label efficiency

Identical to label-efficiency protocol v1 (log1p on ten count/volume/duration features,
standardization on the unlabeled pool; budgets 16, 32, 64, 128, 256, 512, all; seeds 0–2;
balanced sampling; P = Data24 encoder paired with seed, R = scratch, N = Mahalanobis on
labelled benign; 60 epochs, Adam 1e-3, class-balanced loss, no model selection), with pool
= S0 units and test = S1 units.

Decision rules: Δ(k) = mean BA(P) − mean BA(R). **Helps** if Δ ≥ 0.05 for at least two of
k ∈ {16, 32, 64} and Δ ≥ −0.02 for every k; **no benefit** if |Δ| < 0.05 for all of
k ∈ {16, 32, 64}; **hurts** if Δ ≤ −0.05 for at least two; **mixed** otherwise.

## Secondary view – global windows

C0, AB1-frozen and N1-Mahalanobis on global windows with the same baseline interval and
S1 test, reported for comparison with Data22/ToN-IoT; not used for any decision.

## Limits declared in advance

Attack units come from four source hosts, all in one /24; synthetic attacks (IXIA);
the Argus→Zeek state mapping and transaction-byte semantics differ from Data24; two
sessions; correlated units; no significance testing; S0→S1 is a 27-day gap, so baseline
and test periods still differ, but benign and attack test units share the same minutes.
