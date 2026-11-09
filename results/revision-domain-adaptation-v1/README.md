# Label-free benign-baseline adaptation of the frozen Data24 model

Question: can the frozen Data24 checkpoint become usable on a different network **without
retraining and without attack labels**, using only an initial period of traffic that the
receiving organization treats as normal? Inference only; no model parameter is fitted.

`protocol.md` (SHA-256 `e2d728c8…`) was frozen before any prediction for these
configurations. The earliest capture dates of each target dataset form the baseline
(Data22: 9–12 Jan 2022, 5,760 windows; ToN-IoT: 2–3 Apr 2019, 2,295 windows); everything
else is test. Released labels confirm that both baselines contain only benign windows;
labels were not used to fit anything.

| ID | Standardization | Decision |
| --- | --- | --- |
| C0 | Data24 training scaler | six-class argmax collapsed to benign/attack (reference) |
| A | re-estimated on target baseline | six-class argmax collapsed |
| B1 / B5 | Data24 training scaler | `1 − P(benign)` above the 99th / 95th baseline percentile |
| AB1 / AB5 | re-estimated on target baseline | `1 − P(benign)` above the 99th / 95th baseline percentile |

Criteria (per dataset): improvement if balanced accuracy ≥ 0.70 and FPR ≤ 0.30; negative
if balanced accuracy < 0.60; otherwise inconclusive. Label-free generalization is supported
only if the improvement criterion holds on **both** datasets.

## Results (test windows)

Data22: 4,258 benign and 110 attack test windows. ToN-IoT: 593 benign and 5,046 attack.

| Config | Data22 BA | Data22 FPR | Data22 recall | ToN-IoT BA | ToN-IoT FPR | ToN-IoT recall | Verdict |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| C0 | 0.526 | 0.003 | 0.055 | 0.500 | 1.000 | 1.000 | negative / negative |
| A | 0.500 | 1.000 | 1.000 | 0.506 | 0.988 | 1.000 | negative / negative |
| B1 | 0.524 | 0.007 | 0.055 | 0.500 | 0.000 | 0.000 | negative / negative |
| B5 | 0.528 | 0.035 | 0.091 | 0.500 | 0.000 | 0.000 | negative / negative |
| **AB1** | **0.911** | **0.005** | **0.827** | **0.873** | **0.194** | **0.940** | **improvement / improvement** |
| AB5 | 0.947 | 0.034 | 0.927 | 0.880 | 0.239 | 0.999 | improvement / improvement |

AUROC of the score: Data22 0.725 (source scaler) → 0.987 (baseline scaler); ToN-IoT
0.835 → 0.879.

**Under the predeclared criteria, AB1 (primary) and AB5 support label-free
generalization on both external datasets. Neither ingredient works alone.**

## Why neither ingredient works alone

- **A alone** shifts every window, attacks and benign alike, far from the Data24 decision
  boundary; the argmax rule then flags everything (Data22 FPR 1.00).
- **B alone** fails because, under the Data24 scaler, target scores saturate near 1 even on
  the baseline (ToN-IoT baseline alert rate 0.997 under C0); the 99th baseline percentile
  lands at the ceiling and nothing exceeds it.
- **A + B**: baseline-relative scaling restores a usable ranking (Data22 AUROC 0.99) and the
  baseline percentile turns it into a calibrated alert rule.

## Post-hoc diagnostic (not part of the protocol)

Breakdown of AB1 decisions:

| Dataset | Benign test windows by period | Alerts |
| --- | --- | ---: |
| Data22 | 13–15 Jan (no attacks on these dates) | 23 / 4,258 (0.5%) |
| ToN-IoT | 4 Apr (no attacks on this date) | 2 / 471 (0.4%) |
| ToN-IoT | 24–29 Apr (benign minutes on attack dates) | 113 / 122 (93%) |

ToN-IoT attack recall by source type: ddos 1005/1006, dos 518/518, injection 260/261,
password 840/842, ransomware 91/93, scanning 236/243, xss 418/418, backdoor 1295/1563,
mitm 82/102. Data22: reconnaissance 88/107, discovery 3/3.

**Reading.** Benign traffic on new days without attacks is rarely flagged (≈0.5%), and
attacks of every family are detected, including MITM, which no Data24 class represents.
However, almost every benign window recorded *during attack periods* is flagged. Two
explanations remain open and cannot be separated with these data: those benign minutes
may be genuinely perturbed by surrounding attack activity (shared hosts, network load), or
the rule partly acts as a detector of departure from the baseline period. Data22 has no
benign windows on attack dates, so the same check is impossible there.

## Claim boundary

Supported: with a short benign baseline and no attack labels, re-estimating
standardization and the alert threshold makes the frozen Data24 model usable on two
independent networks under the predeclared criteria, and both steps are necessary.

Not supported: that the rule distinguishes attacks from *all* benign variation (benign
minutes during attack periods are mostly flagged); that the six-class tactic output
transfers (only the binary alert is evaluated); deployment readiness. Single checkpoint,
correlated windows, no significance testing. The baseline is assumed clean by the
receiving organization; a contaminated baseline would raise thresholds and lower recall.

```bash
.venv/bin/python scripts/domain_adaptation_eval.py   # refuses if protocol digest differs
```
