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

## Remaining runtime gate

The core numerical and adverse-case tests are implemented. The runtime gate
still requires generation and preservation of the signed/frozen attack sets,
evaluation of every configured aggregator on those exact bytes, repeated seeds,
and a digest-verified comparison report. M6 is not complete until that campaign
has been executed and independently verified.

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

For example, freeze three deterministic model-replacement attackers from round
11 of the accepted M5 campaign:

```bash
fl-forensics m6-freeze \
  --source-round-workspace artifacts/m5-secure-multiround-v2/rounds/round-011 \
  --trust-workspace artifacts/m4-trust \
  --partition-workspace artifacts/m3-data24-parquet-iid \
  --output artifacts/m6-model-replacement-f3 \
  --attack model_replacement \
  --f 3

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
  --output artifacts/m6-model-replacement-f3-comparison

fl-forensics m6-verify \
  --frozen-workspace artifacts/m6-model-replacement-f3 \
  --partition-workspace artifacts/m3-data24-parquet-iid \
  --workspace artifacts/m6-model-replacement-f3-comparison
```

The verifier recomputes every aggregate model and the validation, test, and
benign-only temporal-holdout metrics. Altering one frozen update, model, metric,
input ordering, configuration digest, or partition reference makes the gate
fail. Label flip and backdoor scenarios retrain only the designated compromised
clients from copies of their frozen local snapshots. Prototype aggregation is
kept out of this model-parameter comparison and remains the next separate M6
artifact family.
