# Prototype re-anchoring in the Data24 embedding space

PROTEAN-style question: is the encoder representation learned on Data24 a better space for
baseline-relative detection than the raw 25 features? The benign prototype is re-anchored
on each target's benign baseline (no labels); score = Mahalanobis distance to it, alert
above the 99th baseline percentile. `protocol.md` (SHA-256 `035e7e36…`) fixed everything
before any score was computed. Targets, baselines and tests are those of the earlier
studies (Data22, ToN-IoT global windows; UNSW-NB15 source-host × minute units).

## Results (test balanced accuracy, Mahalanobis to the re-anchored benign prototype)

| Representation | Data22 | ToN-IoT | UNSW-NB15 |
| --- | ---: | ---: | ---: |
| RAW features (baseline-standardized) | **0.998** | 0.893 | **0.951** |
| EMB-D24 frozen / s342593 / s343593 | 0.998 / 0.998 / 0.997 | 0.894 / 0.895 / 0.894 | 0.870 / 0.879 / 0.896 |
| EMB-D24 mean | 0.998 | 0.894 | 0.882 |
| EMB-RAND seeds 0 / 1 / 2 | 0.997 / 0.998 / 0.998 | 0.855 / 0.893 / 0.853 | 0.765 / 0.768 / 0.733 |
| EMB-D24 with Data24 scaler (secondary) | 0.663–0.991 | 0.713–0.722 | 0.695–0.722 |

Δ_raw (EMB-D24 − RAW): −0.001, +0.001, −0.070. Δ_rand (EMB-D24 − EMB-RAND): −0.000, +0.027,
+0.126. **Protocol outcome: `mixed`.** Euclidean distances are worse than Mahalanobis in
every representation (reported in `results.json`).

## Reading

1. **The Data24 encoder learned transferable structure, but not more than the raw
   features carry.** Its embedding beats untrained encoders clearly on UNSW-NB15 (+0.13) and
   slightly on ToN-IoT (+0.03), consistently across three Data24 models, so training is
   not irrelevant. Yet it never beats baseline-relative distance on the raw features: equal
   on Data22 and ToN-IoT, 0.07 worse on UNSW-NB15.
2. **Re-anchoring matters more than the space.** With the Data24 scaler instead of
   baseline standardization, every embedding drops sharply (e.g. ToN-IoT 0.89 → 0.71).
3. **Data22 discriminates nothing**: every representation, random included, reaches ≈ 0.998
   (the period effect noted before).

## Consequence

The prototype idea confirms the earlier picture from a different angle: what transfers is
the reference to the target's own benign behaviour. The federated Data24 encoder retains
some general structure about unusual traffic (better than random projections), but
compressing the 25 features through it loses information that a simple distance on the
standardized features keeps.

```bash
.venv/bin/python scripts/prototype_reanchoring.py   # refuses if protocol digest differs
```
