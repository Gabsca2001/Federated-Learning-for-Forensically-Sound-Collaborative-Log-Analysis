# Addendum: pre-declared counts-only hypothesis (v1)

Written at 2026-11-09T22:22:25Z (UTC), while the Data24-only training phase was
still running. `protocol.md` is unchanged (SHA-256
`7dd43cc6e18abf8b72dbd3fd65353de6ac270ad356e0c854de251fef652b1e7c`, verified
at the time of writing). This addendum adds a separate hypothesis. It does not
modify the primary selection rule, its criteria, or the ablation reading in
`protocol.md`.

## 1. Origin of the hypothesis

The variant `counts-only` uses log1p on the 10 quantitative measures:
`connection_count`, `unique_destination_count`, `unique_destination_port_count`,
`duration_mean`, `duration_std`, `duration_max`, `originator_bytes_sum`,
`responder_bytes_sum`, `originator_packets_sum` and `responder_packets_sum`.
It is followed by z-score fitted on Data24 train only.

The hypothesis was formulated earlier, from the exploratory Data22 experiment
(thesis section 5.4.2: Data22 F1 0.81 ± 0.13, recall 0.97, FPR 0.5%). Those
figures are as stated by the user; this addendum did not recompute them. As
`scripts/revision_federated_generalization.py` records, that Data22 follow-up
was itself external-guided and exploratory.

On ToN-IoT, `counts-only` is therefore evaluated as a **pre-declared
confirmatory hypothesis**, separate from the primary Data24-validation
selection in `protocol.md` §4. It is reported regardless of whether the primary
selection picks it, and it does not replace or alter that selection.

## 2. Criterion

These criteria are evaluated on the primary occurrence view (7 934 windows),
using the mean over the 3 seeds (341593, 342593, 343593). Each run uses its
Data24-validation-selected round, the argmax 6-class rule collapsed to binary,
and no ToN-IoT fitting. The frozen baseline is BA 0.5013 and FPR 0.9972.

- **Improvement**: mean balanced accuracy > 0.70 **and** mean FPR < 0.50.
- **Negative**: mean balanced accuracy < 0.60.
- **Inconclusive**: any other outcome. This includes BA > 0.70 with FPR ≥ 0.50,
  and BA in [0.60, 0.70].

The exact-projection view is reported as a sensitivity check only. AUROC and AP
are reported but do not enter this criterion.

## 3. State at the time of writing

- **No ToN-IoT prediction has been computed yet** for any variant or seed of
  this study. The evaluation phase has not been started.
  `selection-before-ton-iot.json` and `ton-iot-results.json` do not exist.
  The ToN-IoT window files have been hashed but not loaded by this study.
- At the time of writing, the training log showed Data24 validation macro-F1
  for some runs (`standard`, `log1p`), but not yet for `counts-only`. These are
  Data24 numbers only and play no role in this criterion.
- The evaluation script (`scripts/ton_iot_robust_transfer.py evaluate`) already
  computes every metric required here for `counts-only`. No code change is
  needed to apply this criterion.
