# Controls for the label-free baseline adaptation result

Does the AB1 result (`results/external-data/revision-domain-adaptation-v1`) show that knowledge learned on
Data24 transfers, or only that adapting to a benign baseline works? `protocol.md`
(SHA-256 `89d89b24…`) fixed the controls and decision rules before any control prediction.
Same datasets, baseline/test dates, baseline standardization and 99th-percentile baseline
threshold as the parent study.

- **N1:** novelty detectors fitted on baseline windows only, no Data24 knowledge
  (max |z|, Mahalanobis, kNN k=5, Isolation Forest).
- **N2:** the same network architecture with random weights (seeds 0, 1, 2).
- **N3:** the three Data24 `standard` FedAvg models selected on Data24 validation
  (seeds 341593, 342593, 343593; trained on CUDA). Seed 341593 reproduces the frozen
  checkpoint's decisions.

## Results (test windows; balanced accuracy / FPR / attack recall / AUROC)

| Scorer | Data22 | ToN-IoT |
| --- | --- | --- |
| **AB1-frozen** (reference) | 0.911 / 0.005 / 0.827 / 0.987 | 0.873 / 0.194 / 0.940 / 0.879 |
| N1 max \|z\| | **0.998** / 0.004 / 1.000 / 0.999 | 0.842 / 0.206 / 0.889 / 0.929 |
| N1 Mahalanobis | **0.998** / 0.004 / 1.000 / 0.999 | **0.893** / 0.212 / 0.998 / 0.978 |
| N1 kNN | 0.997 / 0.005 / 1.000 / 0.999 | **0.893** / 0.212 / 0.998 / 0.933 |
| N1 Isolation Forest | 0.998 / 0.004 / 1.000 / 0.998 | 0.718 / 0.027 / 0.464 / 0.922 |
| N2 random s0 / s1 / s2 | 0.796 / 0.520 / 0.503 (BA) | 0.616 / 0.595 / 0.707 (BA) |
| N3 Data24 s341593 | 0.911 / 0.005 / 0.827 / 0.988 | 0.873 / 0.194 / 0.941 / 0.879 |
| N3 Data24 s342593 | **0.597** / 0.005 / 0.200 / 0.867 | 0.894 / 0.201 / 0.989 / 0.898 |
| N3 Data24 s343593 | 0.966 / 0.004 / 0.936 / 0.996 | 0.751 / 0.194 / 0.695 / 0.873 |

Δ_N1 (AB1 − best N1, BA): **−0.087** on Data22, **−0.020** on ToN-IoT.
Δ_N2 (AB1 − best N2, BA): +0.115 on Data22, +0.166 on ToN-IoT.

**Protocol outcome: `mixed`; N3 model-stable: no.**

## What this establishes

1. **Transfer of Data24 knowledge is not shown.** The frozen Data24 model never beats the
   best novelty detector built from the baseline alone: it is clearly worse on Data22 and
   comparable (slightly worse) on ToN-IoT. The improvement reported by AB1 is explained by
   the baseline adaptation, not by what the model learned on Data24.
2. **Training on Data24 is not irrelevant.** Trained models beat untrained networks with
   the same architecture by 0.12–0.17 BA, so the learned encoder carries some general
   "unusual traffic" structure; it is simply not better than direct distance from the
   baseline.
3. **The Data24 route is model-unstable.** Changing only the seed changes Data22 BA from
   0.597 to 0.966 and ToN-IoT BA from 0.751 to 0.894; one seed fails the improvement
   criterion on Data22.
4. **Data22 cannot discriminate between methods.** A max-|z| rule reaches BA 0.998: the
   attack days are trivially separable from the January baseline. Combined with attacks on
   dates disjoint from all benign windows, the Data22 test measures departure from the
   baseline period more than attack recognition.
5. **ToN-IoT is harder and more informative.** Even the best detectors keep FPR ≈ 0.21,
   driven by the attack-date benign minutes whose HTTP/SF profile the baseline never
   contains (see the parent study's follow-up).

## Consequence for the generalization claim

Supported: a short benign baseline enables label-free alerting on both independent
datasets, and baseline-relative novelty detection performs at least as well as the
adapted Data24 classifier.

Not supported: that the federated Data24 classifier generalizes to new networks, or that
its learned knowledge adds detection value beyond baseline-relative novelty detection on
these datasets.

Limits: benign and attack windows remain on disjoint dates in both datasets, so no scorer
can fully exclude a period-change effect; one baseline choice; correlated windows; the
best-of-N1 comparison is deliberately conservative against the Data24 model.

```bash
.venv/bin/python scripts/domain_adaptation_controls.py   # refuses if protocol digest differs
```
