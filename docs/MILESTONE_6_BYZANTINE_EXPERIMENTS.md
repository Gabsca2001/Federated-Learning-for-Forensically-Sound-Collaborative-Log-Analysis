# Milestone 6 — Byzantine experiments and robust aggregation

M6 evaluates semantic poisoning after the M5 structural and cryptographic gate.
A compromised but enrolled client can produce a tensor with the correct shape,
bind it to the correct round, and sign it with its TPM-backed ESK.  M5 therefore
establishes attribution and byte integrity, while M6 asks whether the admitted
numeric contribution is consistent with the benign client population.

## Frozen-input comparison contract

Every attack scenario produces one content-addressed set of client deltas.  The
set is immutable and is supplied unchanged to FedAvg, coordinate median,
trimmed mean, MultiKrum, and Bulyan.  An aggregator is not allowed to regenerate
local training or receive a different random attack realization.  The scenario
manifest records the clean source update, attacked update, client identity,
attack parameters, seed, clipping decision, and every output digest.

Model parameters and class prototypes remain separate artifact families.
Prototype poisoning cannot be hidden inside a model-parameter result, and its
support/quorum rules are evaluated independently.

## Implemented deterministic primitives

The M6 core provides:

- training-data transformations for label flip and feature-trigger backdoors;
- model-delta transformations for Gaussian noise, sign flip, and model
  replacement;
- deterministic encoder-centroid extraction with local-support filtering,
  support-weighted mean and coordinate-median prototype aggregation, explicit
  class quorum, distance indicators, and class-prototype poisoning;
- byte-equivalent colluding deltas;
- global L2 clipping with an explicit threshold and preserved scale;
- relative norm, cosine-to-median, coordinate-median distance, and MAD
  indicators;
- FedAvg, coordinate median, trimmed mean, MultiKrum, and Bulyan over the same
  validated delta tensors.

Prototype extraction operates on the encoder embedding, not on raw input
features. Each local class record preserves its true support and is emitted only
when it meets the configured minimum. Aggregation requires the configured
number of supporting clients for that class; insufficient quorum is an explicit
result without a prototype vector. Model parameters and prototype vectors never
share an aggregation call or artifact schema. The pure numerical contract is
unit-tested before it is bound to the signed M5 model and partition lineage in a
separate freeze/compare/verify runtime increment.

The numerical functions do not mutate their inputs. Gaussian noise, backdoor
selection, and collusion are deterministic for the recorded seed. Comparison
schema `1.1` also evaluates the round base model and every individual frozen
client model on the server validation split. For client $k$, the semantic
indicator is

\[
I_k = F_{1,\mathrm{macro}}(w_t) - F_{1,\mathrm{macro}}(w_k).
\]

A positive value measures validation degradation relative to the round base.
Schema `1.0` remains reproducible for already preserved comparisons.

Backdoor comparison schema `1.2` adds an aggregate-model targeted evaluation
gate. The
gate selects only server test rows whose original label differs from the frozen
backdoor target, applies the exact recorded feature indices and trigger value,
and then measures

\[
\mathrm{ASR} = \frac{\text{triggered non-target rows predicted as the target}}
                     {\text{all triggered non-target rows}}.
\]

Schema `1.3` additionally evaluates every individual frozen client model on the
same content-addressed triggered set. This distinguishes a backdoor that was
never learned locally from one learned by compromised clients but rejected by
the aggregate defense. The comparison records client, aggregate-model, and
round-base ASR. Their difference from the base is the ASR lift, which prevents a
model's pre-existing target
bias from being misreported as attack-induced behavior. The clean validation,
test, and temporal-holdout results remain in every outcome so attack success and
utility degradation are evaluated separately.

The targeted-evaluation contract preserves the source split, eligibility rule,
target label, feature indices, trigger value, poisoned-training fraction,
original-label counts, row count, and SHA-256 digests of both the eligible source
rows and the triggered rows. Verification reconstructs the triggered set from
the partition snapshot, reevaluates every preserved client and aggregate model,
and rejects any difference in metrics or lineage. Schemas `1.0`, `1.1`, and
`1.2` remain supported for previously frozen comparisons.

Colluding-update comparisons use schema `1.4`. The controlled collusion
primitive produces byte-identical frozen model updates from one explicitly
recorded template client and scale. The comparison groups all 15 contributions
by their already verified frozen-update SHA-256 digest and records the shared
digest, ordered client identities, group size, unique-update count, and exact
peer identities for every client. Verification rejects a declared colluding
scenario when its attackers do not share the same frozen coordination contract
and exact update bytes.

Exact equality is strong evidence of coordination in this controlled campaign,
but is not by itself a universal proof of malicious intent. An operational
decision must also consider the declared training contract, expected sources of
determinism, semantic validation impact, update geometry, aggregate behavior,
and authenticated client provenance.

## Byzantine bounds

Let `n` be the number of admitted updates and `f` the assumed upper bound on
Byzantine contributors. The implementation halts explicitly when a requested
algorithm is outside its declared domain:

- trimmed mean requires `n > 2f`;
- Krum/MultiKrum requires `n >= 2f + 3`;
- Bulyan requires `n >= 4f + 3`.

With 15 participating clients, the core M6 campaign can compare all configured
aggregators for `f` equal to 1, 2, or 3. Invalid configurations are errors, not
silent fallbacks to FedAvg.

## Runtime gate status

The freeze/compare/verify runtime gate has been exercised on seven `f=3`
scenarios derived from the same verified M5 round: the legacy magnitude-only
amplification baseline, targeted malicious model replacement, label flip, sign
flip, Gaussian noise, feature-trigger backdoor, and byte-identical collusion.
Every defense profile was recomputed from the exact ordered frozen bytes and
independently verified by digest. Backdoor evaluation additionally reconstructs
one content-addressed triggered test set for both individual-client and
aggregate-model evaluation. Collusion evaluation groups all admitted updates by
their already verified frozen-update digest.

The remaining M6 campaign covers the separate prototype artifact family, other
configured `f` values, and repeated seeds. M6 therefore remains in progress even
though the current runtime slices are implemented and verified.

## Freezing and comparing one real M5 round

The first runtime integration derives a controlled attack scenario from a
previously verified M5 round. The original bundle and update digests are kept in
the frozen manifest. A model- or data-poisoning transformation is then applied
as if it had occurred inside a compromised client before that client hashed and
signed its contribution. The derived artifact is explicitly labelled as an M6
simulation; it is never presented as the original TPM-signed M5 update.

The authoritative partition reference is the immutable
`public/partition-manifest.json` copy whose SHA-256 digest is bound by the signed
M5 Round Context. M6 preserves that exact copy and checks the bytes of all 15
client datasets, all 15 client manifests, and the server evaluation snapshot
against its per-file digests. A later regeneration of the top-level M3 manifest
may change metadata such as `code_version` without changing those frozen files;
it is not used to replace the signed M5 reference.

The first frozen `model_replacement` scenario is preserved byte-for-byte as a
legacy `update_amplification` baseline. Its manifest retains the historical
attack name because renaming a content-addressed artifact would invalidate its
digest. Semantically, it multiplies a clean local delta by 15 and therefore
retains the benign update direction.

New `model_replacement` scenarios use a genuinely malicious objective. Each
compromised client starts from the signed round base model, trains on its frozen
local snapshot after the configured targeted label flip, computes the malicious
model delta, and submits `base + scale * malicious_delta`. Freezing fails if the
objective changes no local rows. The manifest records the objective, source and
target labels, changed-row count, and replacement scale.

The legacy `configs/byzantine.yaml` remains unchanged because its digest is
bound to the existing frozen experiment. New model-replacement runs use
`configs/byzantine-malicious-model-replacement.yaml`.

For example, freeze three deterministic model-replacement attackers from round
11 of the accepted M5 campaign:

```bash
fl-forensics m6-freeze \
  --source-round-workspace artifacts/m5-secure-multiround-v2/rounds/round-011 \
  --trust-workspace artifacts/m4-trust \
  --partition-workspace artifacts/m3-data24-parquet-iid \
  --output artifacts/m6-model-replacement-f3 \
  --attack model_replacement \
  --f 3 \
  --config configs/byzantine-malicious-model-replacement.yaml

fl-forensics m6-verify-frozen \
  --workspace artifacts/m6-model-replacement-f3
```

The comparison runs FedAvg, coordinate median, trimmed mean, MultiKrum, and
Bulyan both with and without the clean-reference L2 clipping threshold. Every
profile receives the same ordered frozen update set:

```bash
fl-forensics m6-compare \
  --frozen-workspace artifacts/m6-model-replacement-f3 \
  --partition-workspace artifacts/m3-data24-parquet-iid \
  --output artifacts/m6-model-replacement-f3-comparison \
  --config configs/byzantine-malicious-model-replacement.yaml

fl-forensics m6-verify \
  --frozen-workspace artifacts/m6-model-replacement-f3 \
  --partition-workspace artifacts/m3-data24-parquet-iid \
  --workspace artifacts/m6-model-replacement-f3-comparison \
  --config configs/byzantine-malicious-model-replacement.yaml
```

## Verified malicious model-replacement result

The verified run uses round 11, `f=3`, attackers `client02`, `client05`, and
`client14`, a `reconnaissance -> benign` objective, and replacement scale 15.
The three local objectives changed 28, 28, and 29 rows respectively.

- frozen manifest SHA-256:
  `4ff9af4265c58277cb457188a01be553851b3049bb60797cf760db211cd25c66`;
- schema `1.0` comparison SHA-256:
  `abf7be98f4e8f02f2aed689bc22d01acee56c36eac08c31da81b36d18e0aa33d`;
- schema `1.1` comparison SHA-256 with validation impact:
  `32f2300f615684c806be7c1037b77396a5982d8c5657f27d34c71670786e544f`;
- verification: 15 clients, 10 profiles, zero errors;
- regression gate: 84 tests passed and the changed-file Ruff gate passed.

| Profile | Validation macro-F1 | Test macro-F1 | Temporal holdout accuracy |
| --- | ---: | ---: | ---: |
| coordinate median | 0.941689 | 0.914722 | 0.996296 |
| trimmed mean | 0.941689 | 0.914722 | 0.996528 |
| MultiKrum | 0.941390 | 0.918417 | 0.995370 |
| MultiKrum + clipping | 0.941390 | 0.918417 | 0.995370 |
| FedAvg + clipping | 0.939145 | 0.913178 | 0.996991 |
| coordinate median + clipping | 0.938502 | 0.914722 | 0.996065 |
| trimmed mean + clipping | 0.938502 | 0.914722 | 0.996528 |
| Bulyan | 0.938203 | 0.918417 | 0.995370 |
| Bulyan + clipping | 0.938203 | 0.918417 | 0.995370 |
| FedAvg | 0.568438 | 0.543482 | 1.000000 |

Unprotected FedAvg collapses from the legacy amplification result of 0.927722
test macro-F1 to 0.543482. Its test recall for `reconnaissance` is zero, while
benign recall is one and benign precision falls to 0.471667. The perfect
benign-only temporal-holdout accuracy is therefore not robustness evidence; it
is consistent with the attack biasing predictions toward `benign`.

The attacker relative norms are 18.578--20.165, versus 0.858--1.040 for benign
clients. Their cosine-to-median values fall to 0.394--0.416 and MAD scores rise
to 38.952--47.985. Clipping acts only on the three attackers, with scales
0.055646--0.060400, and restores FedAvg to 0.913178 test macro-F1. MultiKrum and
Bulyan obtain the highest test macro-F1, 0.918417. These results demonstrate
that a valid TPM-backed signature establishes origin and integrity, but cannot
establish that the signed update is semantically benign.

The schema `1.1` base validation macro-F1 is 0.928967. Each malicious client
model falls to 0.102938, producing validation impact 0.826029. Benign-client
impact ranges from -0.023644 to 0.055805, so the smallest malicious impact is
approximately 14.8 times the largest benign impact in this frozen scenario.
This is a diagnostic result, not an automatic malicious-intent verdict or a
universal quarantine threshold. Threshold calibration and false-positive
analysis remain bound to clean development campaigns and repeated seeds.

## Verified feature-trigger backdoor result

The verified run reuses round 11, `f=3`, and attackers `client02`, `client05`,
and `client14`. Each compromised client deterministically poisons 48 local
training rows (10 percent) by setting feature indices 0 and 1 to 12 and changing
the label to `benign`. The targeted server evaluation contains all 3,497
originally non-benign test rows after applying the same trigger.

- frozen manifest SHA-256:
  `3b509127fe54bb4be622d7802036702c937ce48e5c62d00193bd01a27c3329d5`;
- schema `1.2` aggregate-ASR comparison SHA-256:
  `d2c160cd0414498e4a4f2281838a2f35d3036e5e5c6bca9afc7bea038f6629df`;
- schema `1.3` client-and-aggregate-ASR comparison SHA-256:
  `04fe1be494ea33bcb0da5d36c7a031366f8ccd14a701e286acc9622c8099d0c4`;
- eligible source-row-set SHA-256:
  `ddb9c0c7849a1ebeaa163bfae7d20e162bb672deff87e46a780d552364aa33ab`;
- triggered-row-set SHA-256:
  `a1abe33fd50f5d547cb7d0f74d61537e1c0ac6dc3acbcbb92edfe60423c096e9`;
- verification: 15 clients, 10 profiles, zero errors;
- regression gate: 85 tests passed and the changed-file Ruff gate passed.

The round base model and all 12 benign client models have zero ASR. The three
attacker models have ASR 0.995711 (`client02`), 0.998284 (`client05`), and
0.995139 (`client14`). The trigger is therefore learned locally and the ASR
indicator separates the compromised and benign clients in this frozen
scenario. In contrast, ordinary validation impact does not: `client05` has
impact -0.001592 and therefore slightly improves validation macro-F1, while the
other two attacker impacts overlap the benign range.

| Profile | Test macro-F1 | Backdoor ASR | ASR lift from base |
| --- | ---: | ---: | ---: |
| coordinate median | 0.918822 | 0.000000 | 0.000000 |
| coordinate median + clipping | 0.918822 | 0.000000 | 0.000000 |
| MultiKrum | 0.918417 | 0.000000 | 0.000000 |
| MultiKrum + clipping | 0.918417 | 0.000000 | 0.000000 |
| Bulyan | 0.918417 | 0.000000 | 0.000000 |
| Bulyan + clipping | 0.918417 | 0.000000 | 0.000000 |
| trimmed mean | 0.914856 | 0.000000 | 0.000000 |
| trimmed mean + clipping | 0.914856 | 0.000000 | 0.000000 |
| FedAvg + clipping | 0.913009 | 0.000000 | 0.000000 |
| FedAvg | 0.894659 | 0.000000 | 0.000000 |

All aggregate profiles reduce ASR to zero. This demonstrates a locally
successful attack that does not survive aggregation, rather than an attack that
failed to train. Coordinate median preserves the highest clean test macro-F1.
Unclipped FedAvg also removes the trigger behavior but degrades clean test
macro-F1 to 0.894659; zero ASR alone is therefore not evidence that utility was
preserved. Clipping recovers FedAvg to 0.913009. The unchanged schema `1.2`
comparison remains independently reproducible after introducing schema `1.3`,
which confirms verifier backward compatibility.

The result also demonstrates why a generic anomaly or validation score cannot
establish backdoor absence. The forensic decision requires the attack-specific,
digest-bound evaluation set, client-level attribution, aggregate-level ASR, and
clean utility metrics together.

## Verified byte-identical collusion result

The verified run reuses round 11, `f=3`, and attackers `client02`, `client05`,
and `client14`. All three submit the same model update derived from the clean
`client02` delta with scale 15. The controlled derivation therefore tests an
exact coordinated cluster rather than merely three independent large updates.

- frozen manifest SHA-256:
  `f830b26d4a991be0e5146c645da8da0f7bf9ec219d4673cbe7ff02505d442c7c`;
- schema `1.4` comparison SHA-256:
  `ed2ed5516f449addd99342b8434ab5ab3a62f8a8e37024c2815cdabf3789771e`;
- shared attacker update SHA-256:
  `0e1725cdc13f529f051b71939dbb85bd5034c2a815eac4239948ef69d7a18ba6`;
- evidence inventory: 13 unique updates and one exact-duplicate group of size 3;
- verification: 15 clients, 10 profiles, zero errors;
- regression gate: 86 tests passed and the changed-file Ruff gate passed.

The sole duplicate group contains exactly `client02`, `client05`, and
`client14`; every benign client has group size one. Each colluder has relative
norm 14.656, cosine-to-median 0.873, MAD score 25.419, and validation impact
0.492368. Cosine alone is not decisive because several benign updates have a
similar direction. Exact digest grouping, norm, MAD, validation impact, signed
identity, and the declared experiment contract together provide the attribution.

The clean-reference clipping threshold is L2 norm 0.533394518, derived from
clean median 0.464454602 and MAD 0.022979972. Clipping applies scale 0.076562132
to exactly the three colluding clients and scale 1 to all 12 benign clients.
This independently agrees with the digest-defined group without using the
declared attacker labels to calculate the threshold.

| Profile | Validation macro-F1 | Test macro-F1 |
| --- | ---: | ---: |
| coordinate median | 0.948505 | 0.924420 |
| trimmed mean | 0.948505 | 0.924420 |
| FedAvg + clipping | 0.947671 | 0.924163 |
| coordinate median + clipping | 0.947671 | 0.924163 |
| MultiKrum + clipping | 0.947671 | 0.924059 |
| trimmed mean + clipping | 0.947350 | 0.923830 |
| MultiKrum | 0.941390 | 0.918417 |
| FedAvg | 0.938281 | 0.943052 |
| Bulyan | 0.938203 | 0.918417 |
| Bulyan + clipping | 0.938203 | 0.918417 |

Validation-only selection chooses coordinate median or trimmed mean, both with
0.948505 validation and 0.924420 test macro-F1. Unclipped FedAvg has the highest
reported test value, 0.943052, but lower validation, 0.938281. It cannot be
selected retrospectively from the test result without violating the frozen
evaluation protocol. The validation/test disagreement is preserved as evidence
rather than reported as a successful defense or a successful attack.

This controlled collusion is detected exactly, but it does not produce a
test-set degradation in the unprotected aggregate. It therefore demonstrates
coordinated-update detection and defense comparison, not successful semantic
poisoning. A detected anomaly is not equivalent to harmful impact, just as
cryptographic validity is not equivalent to benign semantics. Repeated seeds,
other `f` values, and end-to-end signed malicious-client campaigns remain
necessary for generalization beyond this frozen case.

The verifier recomputes every aggregate model and the validation, test,
backdoor-targeted (when applicable), and
benign-only temporal-holdout metrics. Altering one frozen update, model, metric,
input ordering, configuration digest, or partition reference makes the gate
fail. Label flip and backdoor scenarios retrain only the designated compromised
clients from copies of their frozen local snapshots.

## Separate prototype-poisoning artifact family

Prototype poisoning is intentionally kept out of the model-parameter comparison.
It is implemented as a separate post-training overlay on the verified global
checkpoint of the selected M5 round. This is not prototype-aware training and it
must not be described as the PROTEAN objective. PROTEAN remains a separate
non-IID experiment with its own validation lock and final evaluation.

`m6-prototype-freeze` first verifies the complete M5 round, binds the signed M5
copy of the IID partition manifest, and loads `checkpoint/global-model.json`.
For each of the 15 clients it passes the frozen training rows through that
checkpoint encoder and computes one centroid per eligible class. A class is
eligible only with at least five local observations. The artifact preserves the
clean and submitted centroid records, their supports, the attacker identities,
and every relevant SHA-256 digest. It never preserves row-level embeddings and
does not access validation, test, or temporal-holdout rows.

For the declared attackers, the reconnaissance centroid is moved toward and
through the benign centroid with scale 1.5. Support is preserved so that the
attack changes only the submitted vector. `m6-prototype-verify-frozen`
independently verifies M5 again, re-extracts all 15 clean centroids, reapplies
the declared transformation, and requires byte-identical submissions.

`m6-prototype-compare` evaluates four profiles on exactly the same frozen
submissions: clean and attacked support-weighted means, and clean and attacked
coordinate medians. A class requires a quorum of three clients; missing quorum
halts evaluation. Each aggregate is evaluated with nearest-global-prototype
inference on validation, test, and temporal holdout. The unchanged M5
classification head is reported only as a reference endpoint.

The comparison preserves full confusion matrices and per-class metrics, the
reconnaissance-to-benign attack-success rate, aggregate centroid displacement,
macro-F1 deltas against the corresponding clean counterfactual, and per-client
distance/MAD indicators. Schema `1.1` additionally separates targeted success
from any loss of source-class integrity. It records source recall, total source
misclassification rate, target-class predictions, and predictions into all
other classes. This prevents a stable or improved macro-F1 from concealing a
class-specific degradation when the declared target is not reached. The
verifier remains compatible with schema `1.0` evidence.

`m6-prototype-verify` recomputes encoder inference, every aggregate, and every
metric. A modified submission, aggregate, metric, configuration, checkpoint,
signed partition reference, or evaluation snapshot therefore fails
verification.

## Verified prototype-poisoning result

The controlled run uses the verified M5 round-11 global checkpoint, the signed
IID partition snapshot, `f=3`, and the same attacker identities used by the
other M6 scenarios: `client02`, `client05`, and `client14`. The extraction and
poisoning stage does not access evaluation data.

- frozen manifest SHA-256:
  `39202178879825a8b49915553a2394e72046a64d5362ed11d8068034c1d564bd`;
- backward-compatible schema `1.0` comparison SHA-256:
  `f851239b35584b2858e4bb66261eb53fba4ef8064b80e70e1a7ad9930b9bd72f`;
- schema `1.1` comparison SHA-256:
  `9b11bf2385d257512a1ca5dc87c023385ea8c9c5af91378c58361bb703b49c8d`;
- schema `1.1` comparison implementation SHA-256:
  `74c0a62178102669f25b8ed850bbf193f9a7a896c4ba14a9b6858d637d759823`;
- verification: 15 recomputed client submissions, four recomputed aggregate
  profiles, recomputed model inference, and zero errors;
- regression gate: 93 tests passed and changed-file Ruff checks passed.

The three declared attackers are the three largest reconnaissance-prototype
outliers. Their distances to the coordinate median are 25.457--27.539, their
relative distances are 93.771--101.440, and their MAD scores are
61.686--65.630. The largest benign distance is 0.484, relative distance 1.784,
and MAD score 1.087. This separation attributes the controlled transformation
under the known experimental ground truth. In an uncontrolled deployment the
scores would identify suspicious submissions for investigation, not prove
malicious intent by themselves.

Support-weighted aggregation moves the global reconnaissance prototype by L2
distance 5.261900 and reduces its distance to the benign prototype from
17.887543 to 12.626144. Coordinate-median aggregation limits the displacement
to 0.095305 and changes the source-to-target distance only from 17.864588 to
17.816119.

| Aggregation | Validation source recall | Test source recall | Test source errors | Targeted test ASR |
| --- | ---: | ---: | ---: | ---: |
| clean support-weighted mean | 0.985423 | 0.989537 | 7 / 669 | 0.000000 |
| attacked support-weighted mean | 0.822157 | 0.822123 | 119 / 669 | 0.000000 |
| clean coordinate median | 0.985423 | 0.989537 | 7 / 669 | 0.000000 |
| attacked coordinate median | 0.985423 | 0.989537 | 7 / 669 | 0.000000 |

The support-weighted source-recall deltas are -0.163265 on validation and
-0.167414 on test. None of the additional errors reaches the declared benign
target: the poisoned test profile redirects 40 reconnaissance rows to
exfiltration and 79 to multi-tactic. The targeted attack therefore fails, but
the unprotected aggregate suffers a reproducible non-targeted source-class
integrity loss. The coordinate median preserves the clean confusion row and
has zero recall, misclassification-rate, and targeted-ASR deltas.

The support-weighted test macro-F1 rises from 0.760242 to 0.777814 even while
reconnaissance recall falls by 16.741 percentage points. This is not a defense
success or a beneficial attack: class-wise changes in precision and errors
increase the global average while hiding the source-class degradation. The
result establishes why macro-F1, targeted ASR, geometric indicators, and
source-class integrity must be interpreted together.

The nearest-prototype endpoint remains below the unchanged M5 classification
head: its clean test macro-F1 is 0.760242--0.765478, versus 0.922567 for the
head. This experiment supports the forensic value of prototype evidence and
robust prototype aggregation; it does not establish the post-training
nearest-prototype overlay as a replacement for the operational classifier.
The temporal holdout contains only benign observations, so its six-class macro
F1 of 0.166667 is not a multi-class performance estimate. All four prototype
profiles classify that holdout with accuracy 1.0.

Scale 1.5 is retained as the primary declared scenario. Any later scale or
`f` sweep must be labelled exploratory, preserve every result, and must not
select a preferred configuration retrospectively from test performance.

## Predeclared prototype sensitivity design

The follow-up prototype analysis is explicitly exploratory and uses a
one-factor-at-a-time design. It is not a new model-selection phase. The primary
anchor remains `f=3`, scale 1.5, with its already observed schema `1.1` result.
The `f` sweep holds scale at 1.5 and evaluates `f=1,2,3`. The scale sweep holds
`f=3` and evaluates 0.5, 1.0, 1.5, and 2.0. Their geometric meanings are,
respectively, the midpoint between source and target, replacement by the target
prototype, half a source-target distance beyond the target, and reflection of
the source through the target. The union contains six unique cells.

Attacker sets are nested and fixed before execution: `client02`; `client02` and
`client05`; then `client02`, `client05`, and `client14`. Every cell receives its
own effective configuration, frozen submissions, aggregates, comparison, and
digest chain. The campaign records every cell and sets both
`test_based_selection_permitted` and `selection_performed` to false.

`m6-prototype-sensitivity` executes the six-cell design and emits one immutable
summary rather than ranking or selecting a scenario. The summary preserves the
targeted ASR, source-class recall and misclassification, macro-F1, and prototype
shift for baseline and robust aggregation. `m6-prototype-verify-sensitivity`
re-extracts all frozen client prototypes, recomputes every aggregate and model
inference, and reconstructs the report-all summary. Repeated random seeds,
dispersion, and confidence intervals remain M8 work and are not inferred from
this deterministic M6 sensitivity analysis.

Before execution, `m6-prototype-sensitivity-plan` exposes the ordered cells,
nested attacker identities, campaign-configuration digest, primary anchor, and
the false test-access/selection flags. The plan can therefore be committed and
published before any new sensitivity result is observed.

## Verified prototype sensitivity result

The predeclared six-cell campaign completed without selecting or suppressing a
scenario. `m6-prototype-verify-sensitivity` independently re-extracted the
client prototypes and recomputed all frozen scenarios, four-profile
comparisons, confusion matrices, per-class metrics, and the report-all summary.

- campaign configuration SHA-256:
  `37918141f170ad4048295a4a5ba508f848d09a54a65ade3144505aa382e99f39`;
- sensitivity SHA-256:
  `d8f8d8c1fc54f007583198b63eb471c6c6ca7810b388baae664e44adf9e0c47f`;
- campaign manifest SHA-256:
  `84cdfa3733963af1673fbf74b18f250a7d3185b9da1aee27137f3d4e70999726`;
- primary anchor: `f3-scale-1p5`;
- result policy: six of six scenarios reported, no test-based selection, zero
  verification errors.

| Scenario | Baseline prototype shift | Baseline test source-recall delta | Baseline test macro-F1 delta | Robust test source-recall delta |
| --- | ---: | ---: | ---: | ---: |
| `f1-scale-1p5` | 1.661660 | 0.000000 | +0.001491 | 0.000000 |
| `f2-scale-1p5` | 3.462868 | -0.056801 | -0.004131 | 0.000000 |
| `f3-scale-0p5` | 1.753967 | 0.000000 | +0.002320 | 0.000000 |
| `f3-scale-1p0` | 3.507933 | -0.056801 | -0.004131 | 0.000000 |
| `f3-scale-1p5` | 5.261900 | -0.167414 | +0.017572 | 0.000000 |
| `f3-scale-2p0` | 7.015866 | -0.917788 | -0.119023 | 0.000000 |

The support-weighted displacement grows with both Byzantine participation and
poisoning scale, but the classification response is nonlinear. In particular,
`f3-scale-1p5` loses 0.167414 source recall while its macro-F1 rises by
0.017572. At scale 2.0 the attacked source recall falls to 0.071749 and the
macro-F1 also collapses. The approximately equal effect of `f2-scale-1p5` and
`f3-scale-1p0` is consistent with total poisoning mass being more informative
than either factor alone in this deterministic run; it is an observation, not
a causal estimate.

The declared benign target is never reached in any cell: targeted test ASR is
zero throughout. The harm is non-targeted redistribution into other attack
classes. Coordinate-median aggregation preserves the clean source recall and
macro-F1 in all six cells while limiting geometric displacement to about
0.05--0.10. These findings are evidence for this fixed checkpoint and client
set, not confidence intervals or population-level generalization.

`m6-prototype-sensitivity-report` accepts only a campaign that first passes the
full sensitivity verifier. It emits a 12-row CSV, a report-all Markdown table,
and six deterministic curves that separately show source recall, macro-F1, and
prototype displacement against `f` and scale. Every file is bound into
`report.json` and `manifest.json` by SHA-256. The report labels extrema as
descriptive and retains the false selection flags.

`m6-prototype-verify-sensitivity-report` repeats the complete source campaign
verification, regenerates every table and PNG byte-for-byte, checks the report
and manifest, and rejects missing, changed, or unexpected report files. The
source scenario directories remain unchanged; the reporting workspace is a
separate derived artifact family.

## Verified sensitivity report

The report was generated from the verified six-scenario campaign and then
accepted by the independent report gate. The verifier recomputed the source
campaign before regenerating all eight derived artifacts: the 12-row CSV, the
Markdown summary, and six PNG curves. No stored metric or stored figure was
trusted as an input to verification.

- report SHA-256:
  `e6fba4e4693b591ed6161ceda3e3de6fde15519c067572a3c6e396a441f89b91`;
- report manifest SHA-256:
  `190414638c3a01df73c43e1afc4926ef7778b5a4028ef8a44ed01f267f590edb`;
- external ZIP SHA-256:
  `ba1d2b85cc666e6511faa7c280a961881e335573da7d84b36be3682c74b15844`;
- rendering backend: Matplotlib 3.11.1, PNG, 180 DPI;
- verified contents: six scenarios, 12 CSV rows, six figures, zero errors;
- forensic controls: source recomputed, report-all policy retained, no
  test-based selection, and byte-identical regeneration of every artifact.

The ZIP digest identifies the transport package and is intentionally separate
from the internal report manifest. The internal manifest binds the logical
report artifacts, whereas a ZIP digest also depends on archive metadata and
packaging order.
