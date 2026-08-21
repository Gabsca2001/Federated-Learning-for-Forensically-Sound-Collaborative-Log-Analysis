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
selection, and collusion are deterministic for the recorded seed.

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

The freeze/compare/verify runtime gate has been exercised on two `f=3`
scenarios derived from the same verified M5 round: the legacy magnitude-only
amplification baseline and a targeted malicious model replacement. All ten
defense profiles were recomputed from the exact frozen bytes and independently
verified by digest.

The remaining M6 campaign covers the other configured attacks, `f` values, and
repeated seeds. M6 therefore remains in progress even though this runtime slice
is implemented and verified.

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
- comparison SHA-256:
  `abf7be98f4e8f02f2aed689bc22d01acee56c36eac08c31da81b36d18e0aa33d`;
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

The verifier recomputes every aggregate model and the validation, test, and
benign-only temporal-holdout metrics. Altering one frozen update, model, metric,
input ordering, configuration digest, or partition reference makes the gate
fail. Label flip and backdoor scenarios retrain only the designated compromised
clients from copies of their frozen local snapshots. Prototype aggregation is
kept out of this model-parameter comparison and remains the next separate M6
artifact family.
