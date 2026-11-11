# Per-key normalised probe: confirmatory live study, verified results

Protocol: [PROTOCOL.md](PROTOCOL.md). Freeze `protocol-before-guard.json` sha256
`2c555054dd649bda131df36858e093ef880cf496333734575849d0f4172a65c6`, committed in 5613783 before training.
Rule, multiplier (2) and floor (0.1) were not changed. The refitted scales matched development exactly.

## Pipeline status

| Step | Outcome |
|---|---|
| calibrate / prepare / smoke | done. The smoke run is not evidence |
| guard (16 clean cases) | independently verified (`revision_probe_keynorm_audit.py guard`); **all 4 arms qualify**, including `probe+bounded` on these partitions |
| evaluation (128 cases, 15 rounds each, all complete) | independently verified, every round rebuilt |
| test | opened only after verification; `cases.csv`, `paired-harm.csv`, `summary.json` from `scripts/report_arm_study.py` |

## Hypotheses (paired worst-trigger peak harm; the seed is the unit; holds if strictly lower in a majority)

| Id | Comparison | lower / higher / equal | Holds |
|---|---|---|---|
| K1 | probek+bounded vs tpm_only+bounded, pair-dba + evasive + adaptive | 19 / 1 / 4 | **yes** |
| K2 | probek+bounded vs tpm_only+bounded, pair-dba + evasive | 15 / 1 / 0 | **yes** |
| K3 | probek+bounded vs tpm_only+fedavg, effective controls only | 17 / 0 / 1 | **yes** |
| K4 (descriptive) | probek+bounded vs probe+bounded, pair-dba + evasive | 6 / 1 / 9 | no (mostly ties: both at 0 in IID) |

## Mean peak / final attack success per cell (4 seeds, %)

| Cohort | Variant | fedavg | bounded | probe+bounded | probek+bounded |
|---|---|---|---|---|---|
| IID | pair-dba | 8.5 / 0 | 5.1 / 0 | 0 / 0 | 0 / 0 |
| IID | evasive | 0.9 / 0 | 0.5 / 0 | 0 / 0 | 0 / 0 |
| IID | adaptive | 100 / 100 | 49.4 / 0 | 45.9 / 0 | 33.7 / 0 |
| non-IID | pair-dba | 54.5 / 5.9 | 55.6 / 15.4 | 21.5 / 6.2 | 10.6 / 6.4 |
| non-IID | evasive | 45.8 / 22.1 | 50.7 / 25.2 | 38.0 / 21.1 | 15.7 / 11.3 |
| non-IID | adaptive | 99.6 / 61.5 | 73.5 / 39.6 | 73.5 / 39.6 | 73.5 / 35.3 |

Clean non-IID bounded arms show a baseline of 9.8%, the same in all three bounded arms. Harm is
measured against each arm's own clean history.

## Secondary endpoints (descriptive)

Attacker client-rounds quarantined during attack rounds (out of 240 per cell):

| Variant | probe+bounded | probek+bounded |
|---|---|---|
| pair-dba | 172 | 232 |
| evasive | 142 | 226 |
| adaptive | 1 | 4 |

Honest clients in **attacked** probek+bounded runs:
* pair-dba and evasive: 0% quarantine, no exclusions.
* adaptive: 0.90% quarantine overall, but **2 of 8 runs have consecutive honest exclusions,
  up to 5 rounds** (iid s2027711001: 2.8%; non-iid s2027720001: 3.9%).
* The predeclared target (≤5% and no run ≥2) is therefore **missed under the adaptive attack**.

Clean runs and the guard had no honest exclusions.

Effective reference controls (≥20 pt harm under FedAvg):
* pair-dba: 7/8
* adaptive: 8/8
* evasive: **3/8**. Under the protocol, the evasive part is reported as **weak live**. The
  K2 evasive comparisons still count, but they rest mostly on non-IID seeds.

## Reading

* Confirmed on fresh partitions: per-key normalisation removes the honest exclusions seen under
  pair-dba and evasive attacks, and it adds protection beyond clipping against the ordinary and the
  probe-aware pair DBA, especially in non-IID (peak 55.6 → 10.6 for pair-dba, 50.7 → 15.7 for evasive).
* Not solved: the adaptive interpolation attacker is almost never quarantined (4/240). In non-IID it
  reaches the same 73.5% peak under every bounded arm. The probek gain in K1 under the adaptive attack
  comes from IID only.
* New failure mode: in 2 adaptive runs the rule repeatedly excluded honest clients. The adaptive
  attacker shifts the global model, so honest excess on some key exceeds 2× its clean scale. Persistence
  is therefore still a risk in attacked conditions. The guard rule only checked clean conditions.
* The deployed raw probe passed the guard on these partitions, unlike the earlier study. Its
  honest-exclusion failure is partition-dependent, not universal.

Cases are archived one tar.gz per case after verification (`artifacts/revision-probe-keynorm-confirm/ARCHIVE-RECORD.json`).
