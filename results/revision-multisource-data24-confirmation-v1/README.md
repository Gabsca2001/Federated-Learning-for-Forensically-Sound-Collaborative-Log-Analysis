# Confirmed: multi-source federation generalizes to an unseen network (held-out Data24)

`protocol.md` (SHA-256 `de2f912b…`) froze the configuration and criteria before this run.
New seeds 3–7 (exploration used 0–2).

## Configuration

FedAvg over **Data22, ToN-IoT and UNSW-NB15** (three clients), each expressing its units as
deviations from its own benign baseline; input view A `[clip(z, ±20), log1p|z|]`; binary
head; 30 rounds; final round. Applied to Data24 with **no Data24 label**: baseline-relative
rank of the logit margin, 5-unit trailing median, alert above the 99th baseline percentile.
Reference: the same pipeline with UNSW-NB15 as the only source.

## Results (Data24 test split: 4,937 windows)

| Arm | BA | FPR | Recall | AUROC | Recall @ 0.1% FPR |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Multi-source (3 networks)** | **0.930** | 0.011 | 0.872 | 0.879 | **0.858** |
| Single source (UNSW-NB15) | 0.518 | 0.009 | 0.045 | 0.127 | 0.026 |

Multi-source BA per seed: 0.888, 0.982, 0.994, 0.895, 0.892.
**Verdict: `confirmed`** (BA ≥ 0.90; recall at 0.1% FPR ≥ 0.50; 5/5 seeds ≥ 0.85; gain over
single source ≥ 0.20).

## Exploratory follow-up: seed ensemble (`exploratory-seed-ensemble.json`)

Averaging the logit margins of the five models into one score: BA **0.975**, FPR 0.012,
recall 0.961, recall at 0.1% FPR 0.959. Ensembles of any three seeds: mean BA 0.969
(0.890–0.983). Averaging ranks instead of margins is worse (0.884). Same seeds as the
confirmation, so this part is exploratory.

## Reading

A single source network does not transfer to Data24 (its attack direction is reversed,
AUROC 0.13), but a federation of three heterogeneous networks does: the model learns
baseline-relative deviation patterns that hold across networks. This supports the thesis
scenario of collaboration among organizations with different traffic.

## Limits

Data24 splits are chronological with benign-only and attack-present date regimes, so
benign and attack test windows are not fully contemporaneous; the Data24 baseline is
chosen by split/benign regime; view A and the multi-source design were chosen while looking
at the three source datasets; numerical FedAvg without the secure pipeline.

```bash
.venv/bin/python scripts/multisource_data24_confirmation.py   # refuses if protocol digest differs
```
