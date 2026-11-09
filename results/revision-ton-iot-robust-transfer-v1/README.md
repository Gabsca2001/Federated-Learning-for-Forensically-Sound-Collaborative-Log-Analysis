# Scale-robust preprocessing for frozen transfer to ToN-IoT

This is the failure-analysis step agreed with the supervisor: after the unchanged Data24
model failed on ToN-IoT (balanced accuracy 0.5013, false-positive rate 0.9972, AUROC
0.8935), test representations less sensitive to feature scale, selected **only on Data24
validation**, without fitting anything on ToN-IoT.

- `protocol.md` (SHA-256 `7dd43cc6…`) was frozen before any training or ToN-IoT inference.
- `addendum-hypothesis.md` (SHA-256 `4d69b976…`) was written during the Data24-only training
  phase, before any ToN-IoT prediction. It pre-declares `counts-only` (log1p on the ten
  count/volume/duration features) as the hypothesis derived from the exploratory Data22
  follow-up (thesis Section 5.4.2: Data22 F1 0.81 ± 0.13). Criteria: improvement if mean
  balanced accuracy > 0.70 and FPR < 0.50; negative if balanced accuracy < 0.60; otherwise
  inconclusive.
- `selection-before-ton-iot.json` closes the Data24 selection before ToN-IoT is opened.
- `ton-iot-results.json` reports every variant and seed; `execution-device.json` records
  that local training ran on CUDA (signed replay manifests still carry the CPU protocol
  label, and CUDA execution is not guaranteed bit-reproducible).

Setup: honest-client FedAvg, 15 IID clients, 30 rounds, three seeds (341593, 342593,
343593), 11 configurations (7 preprocessing variants + 4 feature-group ablations).

## Results (ToN-IoT occurrence view, 7,934 windows, mean over three seeds)

| Variant | Data24 val. macro-F1 | Balanced acc. | FPR | Attack recall | AUROC |
| --- | ---: | ---: | ---: | ---: | ---: |
| **counts-only** (selected) | **0.972** | **0.586 ± 0.012** | 0.621 | 0.793 | 0.597 |
| standard | 0.949 | 0.554 ± 0.068 | 0.890 | 0.998 | 0.904 |
| standard-group-balanced | 0.957 | 0.548 ± 0.060 | 0.902 | 0.998 | 0.818 |
| log1p | 0.955 | 0.651 ± 0.131 | 0.693 | 0.994 | 0.985 |
| log1p-winsor | 0.955 | 0.711 ± 0.099 | 0.565 | 0.986 | 0.972 |
| log1p-winsor-group-balanced | 0.960 | 0.681 ± 0.100 | 0.628 | 0.990 | 0.973 |
| proportions-only | 0.822 | 0.792 ± 0.015 | 0.364 | 0.949 | 0.874 |
| ablate ports/destinations | 0.817 | 0.706 ± 0.047 | 0.569 | 0.980 | 0.880 |
| ablate connection states | 0.974 | 0.513 ± 0.007 | 0.972 | 0.999 | 0.677 |
| ablate byte/packet volumes | 0.949 | 0.518 ± 0.021 | 0.963 | 0.998 | 0.788 |
| ablate durations | 0.901 | 0.512 ± 0.017 | 0.974 | 0.999 | 0.589 |

## Findings

1. **The Data22-derived hypothesis does not transfer.** Data24 validation selects
   `counts-only`, which is also the pre-declared hypothesis. Its balanced accuracy of
   0.586 is below the addendum's negative threshold (0.60), and its AUROC drops to 0.60.
   The primary protocol labels its own verdict `inconclusive` under slightly different
   criteria; under the addendum criteria the outcome is **negative**.
2. **Ports/destinations drive the failure.** Removing only that group raises balanced
   accuracy by 0.15 and lowers FPR by 0.32 relative to `standard` (paired by seed);
   removing any other group makes transfer worse. See
   `results/revision-ton-iot-dataset-differences-v1` for the corresponding feature shift.
3. **Ranking survives, the decision rule does not.** log1p variants reach AUROC 0.97–0.99
   while FPR stays at 0.57–0.69 with large seed variance.
4. **Source validation does not predict transfer.** The best-transferring configurations
   (`proportions-only`, ports ablation) have the lowest Data24 validation scores. These
   are post-hoc observations, not confirmed results.

## Limits

One source dataset, three seeds, correlated windows; no TPM, admission or DBA component.
The frozen-transfer windows and checkpoint are read from the local transfer workspace
recorded in `train-run-record.json`; model checkpoints remain in
`artifacts/ton-iot-robust-transfer-v1` (not tracked).

```bash
.venv/bin/python scripts/ton_iot_robust_transfer.py train      # Data24 only
.venv/bin/python scripts/ton_iot_robust_transfer.py evaluate   # after selection is closed
```
