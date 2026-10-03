# Untargeted adaptive M6: four-seed results

## Completion and provenance

The four-arm untargeted adaptive M6 extension is complete and verified for seeds
342593, 343593, 344593, and 345593. Seed 342593 uses the preserved
`artifacts/m6-adaptive-untargeted-paired-s342593-v1-continuation-v3/` continuation;
the other seeds use their seed-specific v1 workspaces. Each campaign completed
30 rounds in each of `gated_clean`, `gated_adaptive`, `tpm_clean`, and
`tpm_adaptive`: 480 secure rounds total. The adaptive attack is active only in
rounds 11–30, as frozen by the protocol.

The sanitized report is in
[`results/m6-adaptive-untargeted-multiseed-v1/`](../results/m6-adaptive-untargeted-multiseed-v1/README.md).
Its manifest SHA-256 is `5e14ed6e0c9e7d9193ce72a2315d739bc4941a062c13d50df41a3798a2a39778`.
The report's 10-file manifest and all four source completion/execution-lock
receipts were independently checked. It reads preserved test evaluations and
round decisions; it does not rerun test inference. The three figures are
[paired loss](../results/m6-adaptive-untargeted-multiseed-v1/paired-loss-by-seed.png),
[admission outcomes](../results/m6-adaptive-untargeted-multiseed-v1/admission-outcomes.png),
and [validation search success](../results/m6-adaptive-untargeted-multiseed-v1/search-success-by-seed.png).

The locked protocol documents
[`M6_ADAPTIVE_UNTARGETED_LIVE_V1.md`](M6_ADAPTIVE_UNTARGETED_LIVE_V1.md) and
[`M6_ADAPTIVE_UNTARGETED_REPLICATION_V1.md`](M6_ADAPTIVE_UNTARGETED_REPLICATION_V1.md)
were not changed. This results page is separate from their frozen inputs.

## Paired selected-checkpoint test results

Loss is clean test macro-F1 minus adaptive test macro-F1; positive values mean
the selected adaptive checkpoint scored lower. The difference column is
TPM-only loss minus gated-composite loss.

| Seed | Gated-composite loss | TPM-only loss | TPM minus gated |
|---:|---:|---:|---:|
| 342593 | +0.000187 | +0.053343 | +0.053156 |
| 343593 | -0.007300 | +0.001232 | +0.008532 |
| 344593 | +0.000941 | +0.000970 | +0.000029 |
| 345593 | +0.008382 | +0.000000 | -0.008382 |
| Mean | +0.000552 | +0.013886 | +0.013334 |
| Sample SD | 0.006409 | 0.026310 | 0.027431 |

These are descriptive seed-level statistics, not a significance test. The
extension was planned after the exploratory seed 342593 result was known, and
all seeds reuse UWF-ZeekData24; they are not independent dataset replications.
The three added seeds alone have mean losses of +0.000674 for gated-composite
and +0.000734 for TPM-only, with a mean difference of only +0.000060. Their
per-seed differences change direction and size, so these results do not establish
a reproducible predictive-performance advantage for either policy.

A key qualification is seed 342593: its TPM-only adaptive checkpoint was selected
at round 10, before the attack began in round 11. Its +0.053343 loss is therefore
not evidence that the selected model contains a poisoned update. The paired
endpoint compares that pre-attack adaptive checkpoint with the clean run's round
27 checkpoint, so it captures an end-to-end selected-model difference, not direct
poisoning of the selected snapshot. The post-attack validation trajectory below
is consistent with later adaptive checkpoints being held below the earlier
round-10 score. This may indicate attack-induced training or checkpoint-selection
disruption, but remains exploratory. Interpret each seed and selected round
separately.

## Post-attack validation trajectories (descriptive secondary analysis)

The verified `rounds.csv` also permits a per-round validation comparison. For each
seed and policy, the gap is clean validation macro-F1 minus adaptive validation
macro-F1; positive values mean the adaptive arm scored lower. Scores match exactly
through round 10 in every clean/adaptive pair. The adaptive objective starts in
round 11.

| Seed | Gated: mean rounds 11-30 | Gated: round 30 | TPM-only: mean rounds 11-30 | TPM-only: round 30 |
|---:|---:|---:|---:|---:|
| 342593 | +0.001718 | +0.000468 | +0.323491 | +0.285131 |
| 343593 | -0.014646 | +0.000573 | +0.244720 | +0.243296 |
| 344593 | +0.003958 | +0.001426 | +0.152437 | +0.288426 |
| 345593 | -0.004657 | +0.001809 | +0.069036 | +0.004120 |
| Mean of four seed summaries | -0.003407 (SD 0.008334) | +0.001069 (SD 0.000654) | +0.197421 (SD 0.110510) | +0.205243 (SD 0.135646) |

Each seed's active-period value is the mean gap over its 20 attacked rounds. The
mean and sample SD summarize four seed-level values; rounds are not treated as
independent observations. This is a descriptive secondary reanalysis of validation
scores, which the attack optimizer and checkpoint selector already use. It is not
a new held-out endpoint or a significance test.

TPM-only shows a large positive validation gap in all four seeds during rounds
11-30, and at round 30 in three seeds. Gated-composite remains close to its clean
control: the mean seed-level active-period gap is near zero, and round-30 gaps
are small in every seed. This pattern is consistent with the statistical gate
limiting validation degradation in this campaign. The same validation data
drives proposal search and checkpoint choice, however, so this does not establish
a generalization advantage on unseen data.

The TPM-only adaptive checkpoint was selected at round 10 in seeds 342593 and
343593, before the attack began. In seeds 344593 and 345593, the selected adaptive
checkpoints were rounds 23 and 20. Thus the large seed-342593 selected-test loss
can reflect an attack that prevented later checkpoints from becoming competitive
and caused the selector to retain an earlier model; it does not mean that the
selected round-10 snapshot contains an attack update. Its clean comparison also
uses a later selected checkpoint (round 27). For the two seeds whose TPM-only
adaptive checkpoint was selected after attack onset, the selected-checkpoint test
losses are +0.000970 and +0.000000. These two observations are descriptive and
too few for a separate inferential claim. Test inference was not rerun for this
analysis.

## Adaptive-search and admission behavior

The search-success flag means that the frozen optimizer found a feasible proposal
with at least 0.01 absolute validation macro-F1 loss against that round's clean
control. It is a validation criterion, not a test-set attack-success rate.

| Seed | Gated-composite | TPM-only |
|---:|---:|---:|
| 342593 | 4/20 | 19/20 |
| 343593 | 0/20 | 9/20 |
| 344593 | 1/20 | 11/20 |
| 345593 | 0/20 | 7/20 |
| Total | 5/80 | 46/80 |

Across the 240 attacker client-round contributions in adaptive gated arms,
105 were accepted at full weight, 124 were downweighted, and 11 were
statistically quarantined. In the matched TPM-only adaptive arms, all 240
attacker contributions were accepted. The gates also acted on benign contributions;
the report gives the full per-seed denominators and counts rather than treating
those actions as attack detections.

The contrast shows that gated-composite changes which adaptive proposals remain
feasible and how their contributions enter aggregation. The held-out predictive
results do not show a consistent multi-seed effect. Do not infer universal
robustness, causal poisoning success from selected-test loss alone, or
statistical significance from this four-seed exploratory extension.

## Reproduction and outputs

The report generator is `scripts/report_m6_adaptive_untargeted_multiseed_v1.py`.
Its output directory is create-only; to reproduce it, choose a new output path
rather than overwriting the verified snapshot. The report contains `summary.json`,
`per-arm.csv`, `paired-losses.csv`, `rounds.csv`, `admission-summary.csv`,
`search-success.csv`, and the three linked PNG figures. Its README states the
metrics, denominators, and interpretation limits for thesis use.
