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

Likely cause (hypothesis, not tested): z-scores are relative to fixed clean references,
while the natural spread of honest updates changes across partitions and rounds. A
round-relative scale (peers of the same round) would address this, but would be a new
development study.
