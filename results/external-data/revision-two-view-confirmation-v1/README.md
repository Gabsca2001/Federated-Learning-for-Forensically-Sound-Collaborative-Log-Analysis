# Two-view site-relative system trained on Data24: confirmation and in-domain check

## System

Two FedAvg binary classifiers trained **only on Data24**. Every network expresses its units
as deviations from its own benign baseline (z after log1p on count/volume/duration
features). View A = `[clip z, log1p|z|]` (feature identity kept); view B = `log1p|z|` sorted
in descending order (identity-free). Margins are ranked against the target baseline, fused
by MAX, smoothed with a trailing 5-unit median per entity, and thresholded at the 99th
baseline percentile. No label of the target network is used.

## Confirmation on UNSW-NB15 session S0 (protocol frozen beforehand)

`protocol.md` (SHA-256 `a7c0cf6a…`). View B, the MAX rule and persistence had never been
applied to S0. Baseline 2015-01-22 20:00–22:00 UTC (1,960 units). Five seeds, per seed.

Primary test – attack period (2,801 units, 469 attack, same minutes as benign):

| Method | BA | FPR | Recall | AUROC | Recall @ 0.1% / 1% / 5% test FPR |
| --- | ---: | ---: | ---: | ---: | --- |
| NOV (local novelty, same persistence) | 0.963 | 0.075 | 1.000 | 0.950 | 0.000 / 0.000 / 0.704 |
| **SYSTEM (MAX(A,B) + persistence)** | **0.945** | 0.052 | 0.942 | 0.949 | 0.069 / 0.069 / 0.902 |
| View A + persistence (strong-alert tier) | 0.915 | 0.011 | 0.841 | 0.877 | **0.734 / 0.837** / 0.855 |

System BA per seed: 0.903, 0.965, 0.967, 0.960, 0.931. Secondary test (all S0 outside the
baseline, 11,206 units): system 0.959 (FPR 0.024), NOV 0.976 (FPR 0.048), view A 0.917.

**Verdict: `confirmed`** – all four predeclared checks hold (BA ≥ 0.90 with FPR ≤ 0.10;
within 0.02 of NOV; ≥ 4/5 seeds ≥ 0.85; view A recall at 1% FPR ≥ 0.60).

Reading: on S0 the system is slightly below local novelty in balanced accuracy (−0.018)
with fewer false positives; it does not reproduce the small advantage seen on S1 (0.964 vs
0.955, exploratory). Its distinctive contribution is the strong-alert tier: view A finds
73–84% of attacks at 0.1–1% false positives, where novelty finds none.

## In-domain check on Data24 (exploratory, `exploratory-in-domain.json`)

Same recipe, three seeds, Data24 test split:

| Preprocessing | Six-class macro-F1 | Accuracy | Binary BA | Benign temporal-holdout FPR |
| --- | ---: | ---: | ---: | ---: |
| standard (thesis) | 0.902 | 0.982 | 1.000 | 0.0003 |
| view A | 0.913 | 0.985 | 1.000 | 0.0002 |
| view B | 0.874 | 0.947 | 1.000 | 0.0008 |

Site-relative preprocessing does not degrade in-domain performance; view A can replace the
standard input for the six-class task.

## Exploratory figures on the other external datasets (not confirmable: no untouched data)

Seed-averaged, same system: Data22 BA 0.994 (NOV 0.998), ToN-IoT 0.896 (NOV 0.897),
UNSW-NB15 S1 0.964 (NOV 0.955). See `../revision-unsw-s0-confirmation-v1/exploratory/`.

## Limits

One confirmed target (UNSW-NB15, same testbed and attacker hosts in both sessions,
synthetic attacks, Argus state mapping, baseline later than the test period). Design
choices (views, MAX, k = 5) were made on Data22, ToN-IoT and UNSW-NB15 S1. On Data22 and
ToN-IoT attacks and benign traffic lie on different dates. Numerical FedAvg without the
secure pipeline; robustness and forensic experiments of the thesis use the original input.

```bash
.venv/bin/python scripts/two_view_confirmation.py   # refuses if protocol digest differs
```
