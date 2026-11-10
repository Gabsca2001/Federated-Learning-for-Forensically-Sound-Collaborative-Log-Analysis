# Data24 generalization tests on UNSW-NB15 (source-host × minute units)

Third external dataset, used because its source-host × minute units put benign and attack
traffic **in the same minutes**: every one of the 805 attack minutes also contains benign
units. This removes the period confound that limited the Data22 and ToN-IoT studies.
`protocol.md` (SHA-256 `71c9b672…`) fixed splits, scorers and decision rules before any
prediction on UNSW-NB15.

Units: 27,076 (`artifacts/unsw-nb15-host-units-v1`, SHA-256 `29d946b8…`). Baseline
(label-free, assumed normal): S0 units 2015-01-22 14:00–16:00 UTC, 2,162 units, 0 attack
by released labels. Test: S1 (2015-02-18), 13,910 units, 2,737 attack.

## Part 1 – transfer and baseline adaptation (inference only)

Test = all S1 units (the same-minute view gives identical figures to three decimals).

| Scorer | BA | FPR | Attack recall | AUROC |
| --- | ---: | ---: | ---: | ---: |
| C0 frozen, Data24 scaler | 0.580 | 0.816 | 0.977 | – |
| **AB1-frozen** (baseline adaptation) | **0.558** | 0.135 | 0.251 | 0.683 |
| N1 max \|z\| | 0.678 | 0.062 | 0.418 | 0.789 |
| **N1 Mahalanobis** | **0.951** | 0.086 | 0.988 | 0.941 |
| **N1 kNN** | **0.946** | 0.080 | 0.973 | 0.934 |
| N1 Isolation Forest | 0.774 | 0.059 | 0.608 | 0.945 |
| N2 random s0 / s1 / s2 | 0.491 / 0.822 / 0.507 | | | |
| N3 Data24 s341593 / s342593 / s343593 | 0.558 / 0.579 / 0.509 | | | |

**Protocol outcome: `data24_model_worse`** (Δ_N1 = −0.394, Δ_N2 = −0.265); N3 models all
within 0.05 of AB1 (consistently poor). With the six state features neutralized the outcome
is unchanged (Δ_N1 = −0.279), so the Argus→Zeek state mapping does not explain it.

Attacker-host view (S1 units of the four attack hosts: 2,737 attack, 8 benign minutes):
Mahalanobis and kNN flag 7 of the 8 benign minutes of those hosts; Isolation Forest reaches
BA 0.741. With eight benign units this view is descriptive only.

## Part 2 – label efficiency (pool S0, test S1)

| Labelled units | P (Data24 encoder) | R (scratch) | N (novelty) | Δ = P − R |
| ---: | ---: | ---: | ---: | ---: |
| 16 | 0.894 | 0.922 | 0.500 | −0.029 |
| 32 | 0.957 | 0.945 | 0.533 | +0.011 |
| 64 | 0.957 | 0.971 | 0.801 | −0.014 |
| 128 | 0.970 | 0.971 | 0.941 | −0.002 |
| 256 | 0.979 | 0.981 | 0.925 | −0.002 |
| 512 | 0.980 | 0.983 | 0.929 | −0.004 |
| all | 0.996 | 0.996 | 0.807 | −0.000 |

**Protocol outcome: `no_benefit`.** Sixteen labelled units from scratch already give
BA 0.92 one month later.

## Secondary view – global windows

C0 BA 0.750 (FPR 0.50), AB1-frozen 0.362, N1 Mahalanobis 0.480. S1 contains only ten
benign global windows, so this view is uninformative and is not used for any decision,
which is why host × minute units were chosen as the primary unit.

## What this establishes

1. **The frozen Data24 classifier does not transfer to UNSW-NB15**, unchanged (BA 0.58,
   FPR 0.82) or with baseline adaptation (BA 0.56).
2. **Baseline-relative novelty detection works where the period confound is absent.**
   Mahalanobis and kNN distances to two hours of benign traffic, recorded a month earlier,
   separate benign and attack units in the same minutes (BA ≈ 0.95, FPR ≈ 0.08–0.09).
   On Data22 and ToN-IoT this could be a period effect; here it cannot.
3. **Data24 knowledge is worse than no knowledge.** The adapted Data24 classifier is 0.39 BA
   below the best novelty detector and 0.26 below the best untrained network, consistently
   across three Data24 models and with state features neutralized.
4. **Data24 pre-training does not reduce the labels needed** on UNSW-NB15; a few labelled
   units suffice from scratch.

## Limits

Attack units come from four source hosts in one /24, and their few benign minutes are
mostly flagged by distance-based detectors, so host behaviour and attack behaviour are not
fully separable here. Synthetic attacks (IXIA PerfectStorm); Argus states and transaction
bytes differ from Data24 (state sensitivity reported); baseline and test are a month apart;
correlated units; no significance testing; Part 2 is close to ceiling.

```bash
.venv/bin/python scripts/unsw_generalization.py   # refuses if protocol digest differs
```
