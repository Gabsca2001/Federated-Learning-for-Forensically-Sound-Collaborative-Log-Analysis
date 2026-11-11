# head_v2 + clipping: confirmatory study — guard NOT passed

2026-11-11. Predeclared confirmatory replication (`scripts/revision_head_v2_confirm.py`;
protocol `29ee576e…`, confirmatory addendum `7a6077cb…`) of the exploratory result in
`../revision-head-gate-v2-exploratory/`. Frozen head-v2 model reused byte-for-byte
(`301de402…`); fresh partitions (2 IID + 2 non-IID guard, 4 + 4 evaluation), distinct
from every surviving earlier study (partitions of the retired v1/factorial studies
could no longer be compared; seeds are millions apart). Revised clean guard declared
before any outcome: quarantine ≤5%, pooled mass ≥90%, no client excluded in two
consecutive rounds, F1 loss ≤2 points.

## Guard result (12 clean cases, independently verified)

| Arm | IID 2027400001 | IID 2027401001 | non-IID 2027402001 | non-IID 2027403001 | Qualified |
|---|---|---|---|---|---|
| tpm_only+fedavg | ok | ok | ok | ok | yes |
| tpm_only+bounded | ok | ok | ok | ok | yes |
| head_v2+bounded | **Q 11.1%, honest client excluded 7 rounds in a row, F1 loss 3.3 pt** | excluded 2 rounds in a row | ok | ok (1 single-round exclusion) | **no** |

Excluded honest clients are ordinary IID clients (473–474 rows); scores sit just above
the IID threshold (4.16 → 4.2–5.9), mostly on `head_cosine_to_median` and
`relative_norm`/`head_relative_norm`, and become more frequent in later rounds.

## Conclusion

The confirmation **failed at the benign-cost stage**; per the predeclared rule the
evaluation was not run. head_v2's false-positive rate is not stable across partitions:
the fixed clean references calibrated on earlier histories do not transfer to every new
IID assignment, especially late in training when honest updates become small and noisy.
The exploratory attack-containment results therefore cannot be presented as confirmed;
they hold for the assignments on which they were measured. No threshold was changed.

## Clipping confirmation (qualified arms, declared before evaluation)

Declaration: [DECLARATION-BEFORE-EVALUATION.md](DECLARATION-BEFORE-EVALUATION.md)
(sha256 `d48594ea…`). 80 cases (8 fresh assignments × 2 qualified arms × 5 conditions),
all complete, all independently reconstructed; test opened after verification.
Report: `clipping-report/`.

| Hypothesis | lower | higher | equal | Result |
|---|---:|---:|---:|---|
| **K1** clipping vs FedAvg, all attacked variants | **29** | 1 | 2 | **confirmed** |
| K2 effective reference controls only | 28 | 1 | 0 | confirmed |
| per variant: adaptive | 8 | 0 | 0 | |
| per variant: adaptive, head frozen | 8 | 0 | 0 | |
| per variant: distributed DBA | 7 | 0 | 1 | |
| per variant: complete-trigger DBA | 6 | 1 | 1 | |

Clean budgets held on all 8 reserved clean assignments (no benign cost).

Mean test full-trigger peak / final ASR (%), 4 assignments per cell:

| Cohort | Attack | FedAvg | Clipping |
|---|---|---:|---:|
| IID | distributed | 55.0 / 0.0 | 38.2 / 0.0 |
| IID | complete-trigger | 96.8 / 38.7 | 95.9 / 36.3 |
| IID | adaptive | 100.0 / 100.0 | **44.0 / 0.0** |
| IID | adaptive, head frozen | 100.0 / 73.0 | **11.4 / 0.0** |
| non-IID | distributed | 30.8 / 0.0 | 29.7 / 0.0 |
| non-IID | complete-trigger | 55.1 / 32.6 | 54.8 / 26.4 |
| non-IID | adaptive | 90.2 / 60.7 | **51.4 / 3.1** |
| non-IID | adaptive, head frozen | 88.9 / 53.1 | **37.0 / 0.8** |

Per-tensor clipping is confirmed on independent assignments as a cost-free defence that
consistently reduces harm, strongly against scaled (adaptive) updates (final ASR ≈ 0)
and only marginally against complete-trigger DBA, whose poisoned updates are not larger
than benign ones. It is not a complete backdoor defence (peaks of 11–96% remain).

## Likely cause of the head_v2 guard failure

Hypothesis (not tested): z-scores are relative to fixed clean references,
while the natural spread of honest updates changes across partitions and rounds. A
round-relative scale (peers of the same round) would address this, but would be a new
development study.
