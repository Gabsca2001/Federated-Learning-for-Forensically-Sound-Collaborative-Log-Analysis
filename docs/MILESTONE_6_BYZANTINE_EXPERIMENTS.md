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
- class-prototype poisoning and byte-equivalent colluding deltas;
- global L2 clipping with an explicit threshold and preserved scale;
- relative norm, cosine-to-median, coordinate-median distance, and MAD
  indicators;
- FedAvg, coordinate median, trimmed mean, MultiKrum, and Bulyan over the same
  validated delta tensors.

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

The freeze/compare/verify runtime gate has been exercised on six `f=3`
scenarios derived from the same verified M5 round: the legacy magnitude-only
amplification baseline, targeted malicious model replacement, label flip, sign
flip, Gaussian noise, and feature-trigger backdoor. Every defense profile was
recomputed from the exact ordered frozen bytes and independently verified by
digest. Backdoor evaluation additionally reconstructs one content-addressed
triggered test set for both individual-client and aggregate-model evaluation.

The remaining M6 campaign covers collusion, the separate prototype artifact
family, other configured `f` values, and repeated seeds. M6 therefore remains
in progress even though the current runtime slices are implemented and
verified.

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

The verifier recomputes every aggregate model and the validation, test,
backdoor-targeted (when applicable), and
benign-only temporal-holdout metrics. Altering one frozen update, model, metric,
input ordering, configuration digest, or partition reference makes the gate
fail. Label flip and backdoor scenarios retrain only the designated compromised
clients from copies of their frozen local snapshots. Prototype aggregation is
kept out of this model-parameter comparison and remains the next separate M6
artifact family.
