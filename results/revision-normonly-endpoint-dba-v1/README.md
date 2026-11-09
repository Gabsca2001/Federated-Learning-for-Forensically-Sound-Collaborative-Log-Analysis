# Root-norm-only DBA mechanism ablation

Removing cosine weighting does not produce a measured backdoor in these four trajectories. The existing zero-ASR result therefore does NOT identify cosine filtering as necessary: equal-weight root-norm normalization is already sufficient for observed containment in this fixed family.

The separate frozen protocol adds six histories: two clean and four attacked,
using the same two non-IID assignments, 15-client roster, three malicious clients,
warm checkpoint, full 60-row trusted root, 15 rounds, attack rounds 1-10 and
unmodified continuation 11-15 as the learned-endpoint study. The root contributes
only its gradient norm; every nonzero eligible client vector is normalized to
that magnitude and uniformly weighted. Cosine direction filtering and weighting
are removed. Normalization can enlarge small updates; it is not clipping.
The minimum remains ten positive contributors. Pauses cannot become R15 models.

## Matched comparison

All ASRs below are maxima over committed rounds and full/three individual triggers.

| Seed | Poisoned variant | Raw FedAvg peak | Norm-only peak | FLTrust peak | Norm-only rounds | Maximum own-clean F1 loss (points) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 6116104 | distributed | 35.43% | 0.00% | 0.00% | 15/15 | 0.0000 |
| 6116105 | distributed | 100.00% | 0.00% | 0.00% | 15/15 | 0.0000 |
| 6116104 | complete-trigger | 94.40% | 0.00% | 0.00% | 15/15 | 0.0000 |
| 6116105 | complete-trigger | 100.00% | 0.00% | 0.00% | 15/15 | 0.0000 |

Each attacker retrains a poisoned endpoint using 10 Adam epochs at its actual
current parent, then queries factors 0/.125/.5/1/2/4 against its own defender.
Among defined candidates within five F1 points of its own same-round clean
control, it maximizes full-or-single ASR, breaking ties by largest factor.
Undefined outputs stay undefined. Data poisoning and optimizer seeds match the
earlier protocol, but each defense has its own adaptive selections and trajectory.
This is a Byzantine endpoint family, not honest one-step poisoned-data training.

The raw and FLTrust comparators are the immutable previously replayed histories;
their protocol and complete publication checksums are checked before and after
the new run. They are reused controls, not new independent replications.
The 24 first-round factor pairs share the exact parent, root delta and poisoning;
initial-paired-queries.csv isolates operator comparisons before branch divergence.
Later trajectories measure the total effect of changing the operator.

## What this does and does not establish

The maximum attacked-versus-own-clean F1 loss is
0.0000 points; maximum loss versus the
matching clean FedAvg trajectory across all six cases is
0.0000 points.
Own-clean F1 alone cannot establish that clean training progresses sufficiently.
The cases table includes both comparisons, availability and final parameter
distance to own clean. Zero ASR does not establish removal of every poison effect.

This ablation retains the trusted root for magnitude, changes cosine weighting
only, and does not prove root-free security or separate uniform averaging from
normalization. It also does not establish that all trigger components are
necessary: the preceding study found individual components independently
effective in some raw cases. Retrospective group discovery and individual/joint
removal are separate questions. The original ineffective one-step controls and
three pauses remain preserved and cannot be overwritten by this later result.

The starting checkpoint is already trained (initial macro-F1
93.6150%). Cases include clean F1 change from that start, final
parameter displacement, reference-norm range and the sum of per-round magnitude
bounds. A short, small-step warm-start run can preserve an existing classifier
while restricting both useful adaptation and malicious change. It cannot
establish a favorable security-versus-learning trade-off from scratch.

Evaluation reuses 3163 validation rows disjoint from all 60 root rows, with 1733
non-target rows for ASR. There is no new test prediction or independent dataset.
Two assignments, finite factors and 15 rounds do not cover arbitrary adaptive
directions, denial of service, root poisoning, cold starts or long horizons.
Standardized feature values are not demonstrated realizable raw network traffic.
No production defaults, thesis text, TPM evidence or client signatures change.

## Verification and storage

38 focused tests passed: eight new analytical/failure-case tests and the existing
30 endpoint-selection, coherent-context and FLTrust tests. The complete fresh
replay checks 90 rounds and 240 adaptive queries.
Independent arithmetic accounting reconstructs 330 clean/trigger metric
sets from confusion matrices and counts, verifies poisoning budgets and selection,
and checks first-round common-parent comparisons. Replay uses the same numerical
implementation; this is not independent classifier reimplementation.
Experimental evidence is signed by a software research authority, not TPM keys.
Core module hashes, 138 original generation pins and the old capped publication
are checked unchanged. Output retains metadata and final checkpoints only.
