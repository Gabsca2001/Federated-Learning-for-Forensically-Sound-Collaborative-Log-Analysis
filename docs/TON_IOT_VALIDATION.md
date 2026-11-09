# ToN-IoT validation and interpretation

Reviewed on **9 November 2026**. Source acquisition and field mapping are
complete, the original chronological task remains difficult and a separate
offline known-family benchmark demonstrates useful F1 under a different scope.

| Stage | Finding | Evidence |
| --- | --- | --- |
| Official source preflight | 23 files and 22,339,021 rows, with source statistics and 25-feature correspondence checked | [Preflight](../results/revision-ton-iot-preflight-v1/README.md) |
| Unchanged source transfer | 50.13% balanced accuracy and 99.72% false positives | [Frozen transfer](../results/revision-ton-iot-transfer-v1/README.md) |
| Initial target training | Eighteen numerical FedAvg runs; start-only selection is historical | [Initial study](../results/revision-ton-iot-retraining-v1/README.md) |
| Corrected chronological selection | End-time-bounded validation; primary 80.16% mean balanced accuracy with 9/30 benign false positives | [Correction](../results/revision-ton-iot-flow-end-v2/README.md) |
| Chronological F1 extensions | Calibration, regularization, recent-label refits and novelty do not achieve useful F1 for both classes | [F1 assessment](../results/revision-ton-iot-f1-assessment-v1/README.md) |
| Separate known-family benchmark | Mean macro-F1 0.9087, benign F1 0.8778, attack F1 0.9396 and 20.07% false positives across three federated seeds | [Known-family protocol and limits](../results/revision-ton-iot-f1-assessment-v1/README.md) |

## Benign-reference host novelty extension

The [host novelty study](../results/revision-ton-iot-host-novelty-v1/README.md)
fits kNN and Isolation Forest only on 10,000 benign training units, with a
separate benign-only scaler. Thresholds use 6,485 benign validation units with
a primary 1% empirical false-alert budget and a predeclared 5% sensitivity.
Both fixed standalone controls and OR combinations with the three unchanged
classifiers are retained, giving 19 configurations. The detectors require a
centralized trusted benign reference pool; private federated deployment is not
demonstrated.

Validation selects the kNN combination at 1%. Native mean macro-F1 is 0.9086,
with 1.87% FPR and 17-20/130 MITM host units detected, compared with the parent
0.9079, 1.34% and 0-7/130. Common-minute macro-F1 moves from 0.6583 to 0.6812,
with FPR increasing from 15.56% to 20%. The standalone kNN control reaches
0.9176 native macro-F1 and 1.11% FPR but recognizes only 17/130 MITM units.
These are limited exploratory gains, not general unseen-family detection.

The 5% Isolation Forest combination recognizes 61/130 MITM units at 9.72%
native FPR and 66.67% common-minute FPR. Coincident benign alerts remain
separate from attacked-host-supported detection. Calibration budgets do not
guarantee future or combined FPR. Seventy-four focused checks pass, both
detectors are refitted and all 19 configurations are recomputed. Raw CSVs,
prior evidence, the classifier defaults and manuscript remain unchanged.

## Chronological source-IP/minute assessment

The [source-IP window study](../results/revision-ton-iot-host-windows-v1/README.md)
uses the same corrected chronological minute assignments and reconstructs all
7,934 original global windows exactly from 80,172 source-IP/minute aggregates.
All 22,338,152 accepted occurrences remain accounted for. The finer grouping
exposes benign training traffic during attack days without moving MITM into
fitting or validation. Its source-occurrence profile does not claim physical
flow deduplication or an authenticated host identity.

Across three federated seeds, native host/minute test macro-F1 is 0.9079 with
1.34% benign false positives over 4,093 units. On the same 718 global test
minutes, host-score max pooling yields 0.6583 macro-F1 versus 0.6582 for a fresh
global control. The different native metric cannot replace this primary result.
All 586 backdoor minutes have an attacked-host-supported alert, while only
0-7 of 130 native MITM units are detected. In 20-23 MITM minutes per seed, only
benign host units raise alerts. Median MITM attack-row fraction reaches 100%
within host units, so reducing dilution alone does not solve the unseen family.

Sixty-six focused checks pass. Two fresh 30-round replays match all 60 global
tensor digests, all selected scores are recomputed and all four centralized
references are refitted. Source dates remain previously examined; test host
overlap is substantial and no operational, host-independent or general
novel-family guarantee is claimed. The framework default and thesis remain
unchanged. See the new report for unit boundaries, training cap and timing.

## Same-role benign robustness extension

The subsequent [Benign robustness](../results/revision-ton-iot-benign-robustness-v1/README.md) audit locates most parent false positives in later
benign captures: only 0-1 false alerts among 456 benign windows from 4 April,
but 110-119 among 122 later benign windows. All benign training windows are
from 2-3 April. This capture-schedule confound limits interpretation of pooled
F1 even though dates are absent from predictor inputs.

Centering the parent validation threshold gap leaves test confusion matrices
unchanged. Eighteen same-role federated feature ablations and 12 centralized
references compare fractions, per-connection/per-packet rates and augmented
inputs. Validation selects `augmented`, yielding mean test macro-F1
0.9066 with 20.24% false
positives. All outcomes remain reported and no default policy is changed.
Fifty-nine focused checks pass and a new 30-round replay matches every global
tensor digest. This extension does not jointly improve test macro-F1 and benign false positives relative to the parent.

## Two different questions

The chronological assessment fits 6,061 training windows and selects using
1,080 corrected validation windows. The 718-window test has only 30 benign
windows, while MITM is absent from training and validation. A declared recent-data
refit misses 76 MITM windows and recognizes all 586 backdoor windows. All 48
fixed calibration configurations, 16 final refits and 36 novelty combinations
remain reported. These failures are not replaced by the positive benchmark.

The separate benchmark uses within-family chronological 60/20/20 blocks,
conservative observation-end purging and support for every family in all roles.
It has 4,647 training, 1,482 validation and 1,592 test windows, including 578
benign and 21 MITM test windows. Log1p/scaling is fitted on its own training role.
The model receives only the original 25 numeric features. Family names help
allocate roles and training weights, and support stratified evaluation; they
are absent from predictor inputs. Binary-balanced and family-balanced regimes
are compared using validation with a per-family recall constraint.

The validation-selected binary-balanced federated regime yields stable test
macro-F1 from 0.9083 to 0.9090 across three seeds. MITM recall is 19/21 or 20/21,
and the exact-projection sensitivity view gives similar scores. Centralized
Extra Trees achieves 0.9066 macro-F1 on the same population. Dates are globally
interleaved across families and laboratory hosts are shared. Consequently,
these results support known-family learnability, with no claim of global future
generalization, host independence or statistically superior federation.

## Residual limits and checks

Known-family validation macro-F1 near 0.999 falls to about 0.909 on test, with
roughly one false alert in five benign windows. The original unseen-family
chronological test remains unsuccessful. Neither is a fresh blind assessment,
and binomial intervals are descriptive because temporal dependence is not
modeled. Observation ends are conservative proxies from the released fields,
with a one-hour original purge and five-minute within-family diagnostic purge.
Physical connection identity and operational readiness remain unproved.

The parent assessment records 49 focused passes and verifies 828 retained global
checkpoints, recomputes selected federated scores, reproduces eight centralized
references and replays one 30-round trajectory with 450 local updates rerun and
30 matching global tensor digests. This is honest-client numerical IID traffic
classification, not TPM or DBA validation. Original bytes, parent publications
and the manuscript remain unchanged. The earlier source/Data22 checkpoint
discrepancy remains documented in the original transfer evidence.

```bash
make test-ton-iot
make evidence-check STUDY=results/revision-ton-iot-f1-assessment-v1
```

The guarded `ton-iot-f1-study` target requires a fresh `TON_IOT_F1_WORKSPACE`,
verified `TON_IOT_TARGET_WORKSPACE` and `TON_IOT_TRANSFER` paths. It explicitly
launches the fixed chronological F1 study and does not silently launch the
separate diagnostic. Later executed controllers and their specific path bindings
are retained with the new publication. Checkpoints stay in their original
workspace and raw CSVs are not duplicated.
