# Milestone 6 — Byzantine experiments and robust aggregation

> **Pilot multiobiettivo — 2026-09-30:** quattro ricerche validation-only su un round firmato congelato.
> Obiettivi reconnaissance→benign e degrado generale, gated-composite e TPM-only;
> 66 query per cella, verifiche indipendenti completate. Nel caso untargeted il calo
> selezionato è 0,675 pp con gated e 25,297 pp con TPM-only (soglia predefinita 1 pp).
> Non è evidenza su test o training live; vedere il [report e i grafici](../results/m6-adaptive-objectives-ablation-v1/README.md)
> e il [protocollo](M6_ADAPTIVE_OBJECTIVES_ABLATION_V1.md).


> **Completion update — 2026-09-30:** all four adaptive extension pairs are verified.
> The [five-seed report](../results/m6-adaptive-multiseed-v1/README.md) includes paired endpoints,
> trajectories and admission counts. Selected test ASR is 0/669 in both arms for every seed.
> The mean adaptive-minus-clean macro-F1 difference is +0.4038 pp across all five
> seeds (+0.1367 pp for the four new seeds). These are descriptive outcomes, not
> proof of universal robustness or beneficial poisoning. Earlier running/pending
> statements below are historical. The original locked protocol is unchanged.


> **Historical status snapshot (2026-09-29):** the active-policy five-seed comparison, fixed-signal
> sensitivity, live +10% sensitivity, adaptive frozen pilot, signed smoke and paired
> v4 seed341593 are completed. The four additional adaptive seed pairs are running;
> their completion is recorded in the newer update. See [current result index](../results/README.md)
> and [publication checklist](PUBLICATION_READINESS.md). Dated preparation, stopped,
> pending and running notes below are historical execution records, superseded by
> the later completion/recovery entries. Original locked protocols remain unchanged.

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

The completed M6 reference campaign covers the model-update attack family and
the separate prototype artifact family under their declared `f=3` and
sensitivity contracts. Additional fault bounds and repeated random seeds would
strengthen external/statistical validity, but they are not part of this gate.

## Joint TPM/statistical admission pilot

The original architecture deliberately kept two questions separate:

1. M4/M5 asks whether the client identity, TPM-backed signature, attestation,
   freshness, and round binding are valid;
2. M6 asks whether the numeric update is anomalous relative to a clean client
   population.

That separation remains visible in the new artifact, but the decisions are now
evaluated jointly on the same candidate set. Four policies are compared:

- `tpm_only`: an ablation that accepts every trust-valid contribution;
- `statistics_only`: an ablation that ignores identity and attestation;
- `sequential`: hard trust gate followed by the statistical gate;
- `gated_composite`: a documented weighted risk, with failed trust retained as
  a non-compensable veto and an intermediate downweight outcome.

The statistical signal combines relative norm, cosine to the clean median,
coordinate-median distance, MAD score, and validation impact. Each component is
converted to a one-sided robust z-score using medians and MADs from a separate
clean `f=0` freeze of the same verified round. Indicator weights are normalized
and recorded. The quarantine thresholds and downweight quantile are calibrated
from that clean population only; candidate attack labels never enter scoring or
threshold selection.

The verified model-replacement pilot uses round 11 and three controlled
attackers (`client02`, `client05`, `client14`). All 15 observed M4/M5 trust
signals are admissible. The three attacked updates obtain statistical risk
`1.0`; the largest benign candidate risk is about `0.645`. Clean calibration
sets the statistical threshold to `0.818309` and the composite quarantine
threshold to `0.409155`.

| Observed candidate policy | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: |
| TPM only | 0 | 0 | 12 | 3 |
| Statistics only | 3 | 0 | 12 | 0 |
| Sequential | 3 | 0 | 12 | 0 |
| Gated composite | 3 | 0 | 12 | 0 |

This observed population exercises the important “trusted but anomalous”
disagreement: a valid TPM-backed identity does not prove semantic benignity.
To exercise the opposite direction without pretending that M5 admitted an
invalid client, the artifact also contains a policy-evaluation-only 2x2 matrix.
It reuses one verified normal update and one verified attacked update under the
observed passed trust signal and under an explicit counterfactual
`fresh_attestation` failure. The source attestation bytes remain unchanged.

| Controlled matrix policy | Unsafe caught | Safe retained | Unsafe missed |
| --- | ---: | ---: | ---: |
| TPM only | 2/3 | 1/1 | 1/3 |
| Statistics only | 2/3 | 1/1 | 1/3 |
| Sequential | 3/3 | 1/1 | 0/3 |
| Gated composite | 3/3 | 1/1 | 0/3 |

The matrix demonstrates why the one-signal policies remain controls rather
than deployment recommendations. TPM-only misses a trust-valid malicious
update; statistics-only accepts a trust-invalid normal-looking update. Both
integrated policies cover these cells in this pilot. It does not yet establish
population-level detection rates or superiority across attack families.

The clean and attacked M6 workspaces, comparisons, source M5 round, M4 trust
workspace, partition manifest, configurations, and implementation file are all
bound by SHA-256 in `admission.json`. Verification reruns every upstream
verifier and recomputes the complete canonical artifact:

```bash
fl-forensics m6-joint-admission \
  --round-workspace artifacts/m5-secure-multiround-local-test-v1/rounds/round-011 \
  --trust-workspace artifacts/m4-trust-local-test-v1 \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --clean-frozen-workspace artifacts/m6-clean-round11-local-test-v1 \
  --clean-comparison-workspace artifacts/m6-clean-round11-local-test-v1-comparison \
  --candidate-frozen-workspace artifacts/m6-malicious-model-replacement-f3-local-test-v1 \
  --candidate-comparison-workspace artifacts/m6-malicious-model-replacement-f3-local-test-v1-comparison \
  --config configs/composite-admission.yaml \
  --byzantine-config configs/byzantine-malicious-model-replacement.yaml \
  --output artifacts/m6-joint-admission-model-replacement-matrix-local-test-v2

fl-forensics m6-verify-joint-admission \
  --round-workspace artifacts/m5-secure-multiround-local-test-v1/rounds/round-011 \
  --trust-workspace artifacts/m4-trust-local-test-v1 \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --clean-frozen-workspace artifacts/m6-clean-round11-local-test-v1 \
  --clean-comparison-workspace artifacts/m6-clean-round11-local-test-v1-comparison \
  --candidate-frozen-workspace artifacts/m6-malicious-model-replacement-f3-local-test-v1 \
  --candidate-comparison-workspace artifacts/m6-malicious-model-replacement-f3-local-test-v1-comparison \
  --config configs/composite-admission.yaml \
  --byzantine-config configs/byzantine-malicious-model-replacement.yaml \
  --workspace artifacts/m6-joint-admission-model-replacement-matrix-local-test-v2
```

Two limitations apply to the preserved comparison artifact. First, attacked candidate bytes are controlled
M6 derivations and are not covered by the original M5 bundle signatures; the
pilot validates policy scoring and lineage, not a newly signed malicious runtime
submission. Second, the failed-trust matrix cells are counterfactual controls,
not falsely labelled observed M5 admissions.

## Live controlled disagreement experiment

The new `trust-statistical-disagreement.yaml` profile addresses the first limitation without
rewriting the preserved pilot. Its contract is copied into the round's public workspace and its
digest is included in the signed M5 training contract before any client begins local training.
Exactly one client is assigned to each controlled cell; the remaining eleven clients provide a
trusted/normal background population.

For the two statistically anomalous cells, deterministic local training runs normally first.
The client then applies the bound `sign_flip_amplification` transformation, preserves the clean
pre-intervention update, and signs the resulting candidate and metrics with its TPM ESK. The
verifier recomputes the transformation from the signed digest links. This is consequently a
genuine signed runtime contribution rather than an unsigned post-hoc M6 derivation.

For the two trust-inadmissible cells, the experiment deliberately does not falsify M4 evidence.
All observed `active_enrollment`, `tpm_esk_signature`, and `fresh_attestation` checks must pass.
The coordinator preserves that signed decision, then applies a separately recorded, contract-
bound failed-check counterfactual as the input to the four M6 policies. This distinction allows
the policies to be compared on the same numeric update without claiming that a physical or
software TPM actually failed.

The `gated_composite` outcome controls the real effective FedAvg weight. TPM-only,
statistics-only, and sequential outcomes remain shadow ablations over the same inputs. The
round verifier checks all four scenario assignments, both update transformations, both trust
counterfactuals, all policy decisions, and the exact weighted aggregate. Ground-truth labels
are evaluated only after the decisions and never enter the score or thresholds.

Implementation, unit/tamper verification, a fresh-baseline `1.2` Docker/`swtpm` smoke, and the
30-round runtime campaign are complete. Independent verification recomputed all four decisions
for each of the 450 contributions, both controlled interventions, all weighted aggregates, and
the final campaign with zero errors.

Across 30 repetitions of the four controlled cells, the policy-level results are:

| Policy | True positives | False negatives | True negatives | False positives | Unsafe recall |
|---|---:|---:|---:|---:|---:|
| TPM only | 60 | 30 | 30 | 0 | 66.7% |
| Statistics only | 60 | 30 | 30 | 0 | 66.7% |
| Sequential | 90 | 0 | 30 | 0 | 100.0% |
| Gated composite | 90 | 0 | 30 | 0 | 100.0% |

The deployed composite policy contributed 358/450 updates: 334 at full weight and 24 at
reduced weight. It quarantined the 90 controlled unsafe contributions plus two statistically
atypical but declared-safe `client06` contributions at rounds 21 and 26. The strict safe
quarantine rate is therefore 2/360 (`0.56%`). Validation-only selection chose round 11;
isolated test macro-F1 is `0.924554`, compared with `0.935467` in the separate clean campaign
(`-0.010913` absolute). This comparison is descriptive for two deterministic trajectories.

```bash
python scripts/run_m6_disagreement_experiment.py run \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --workspace artifacts/m6-trust-statistical-disagreement-local-test-v1 \
  --trust-workspace artifacts/m4-trust-m6-disagreement-v2 \
  --node-root artifacts/m4-nodes-m6-disagreement-v2 \
  --rounds 30 \
  --workers 4 \
  --attestation-refresh-interval 5
```

The sanitized tables, figures, source bindings, and boundary statements are published in
[`results/m6-trust-statistical-disagreement-local-test-v1/`](../results/m6-trust-statistical-disagreement-local-test-v1/README.md).

### Verifiable explanations of the live training decisions

The earlier contribution-explanation experiment below explains one frozen round and compares
six aggregation mechanisms. The live explanation bundle has a different scope: it follows the
deployed `gated_composite` path across all 30 rounds and explains all 450 decisions that actually
determined the trained trajectory.

For each `(round, client)` slot, `explanations.json` records:

- the signed source decision and Update Bundle digests;
- every M5 trust check and all four shadow/deployed policy outcomes;
- the statistical risk components, exact threshold headroom, and top three named parameter
  tensors by squared distance from the round median;
- the actual nominal/effective FedAvg weight, retained fraction, leave-one-out influence, and
  aggregate displacement that full weight would have caused;
- the client's prior downweight/quarantine history and rank among the 15 round contributions;
- an exact score-level counterfactual for trust-admissible updates, or an explicit hard-veto
  statement when trust is inadmissible.

`index.json` provides round- and client-level counts without replacing the per-contribution
evidence. `manifest.json` binds both payloads, the complete inventories of source decisions,
updates, checkpoints, disagreement contracts, configuration, and the implementation files.
The manifest is content-addressed but not externally time-anchored unless a later M8 package
preserves it.

Generation uses neither attack labels nor test rows. Verification is intentionally expensive:
it re-verifies the complete M5/M6 campaign and reconstructs every explanation byte from the
source workspaces. Historical campaigns are accepted only through explicit allowlists of their
published implementation digests; signatures, contracts, update hashes, decisions, and weighted
FedAvg checkpoints are still recomputed.

```bash
fl-forensics m6-explain-live-contributions \
  --campaign-workspace artifacts/m6-trust-statistical-disagreement-local-test-v1 \
  --trust-workspace artifacts/m4-trust-m6-disagreement-v2 \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --config configs/live-contribution-explanations.yaml \
  --output artifacts/m6-live-contribution-explanations-local-test-v1

fl-forensics m6-verify-live-contribution-explanations \
  --campaign-workspace artifacts/m6-trust-statistical-disagreement-local-test-v1 \
  --trust-workspace artifacts/m4-trust-m6-disagreement-v2 \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --config configs/live-contribution-explanations.yaml \
  --workspace artifacts/m6-live-contribution-explanations-local-test-v1
```

The reference source reconstructs 450 explanations: 334 full-weight acceptances, 24
downweights, 32 statistical quarantines, and 60 hard trust quarantines. These are mechanism
outcomes, not labels of malicious intent. Independent verification passed with zero errors;
the bundle is `m6-live-contribution-explanations-c39cd61a6d17a40691a6928d` and its manifest
SHA-256 is `9d4b30ac3edeafbf1c9a8be7053e280fe28af19b3d44a3d640bfc9fb9e641a6a`.
The thesis-facing snapshot is in
[`results/m6-live-contribution-explanations-local-test-v1/`](../results/m6-live-contribution-explanations-local-test-v1/README.md).

The policy is no longer restricted to retrospective comparison in the codebase.
The optional M5 in-round profile binds the calibration and policy in the signed
training contract, evaluates each newly trained and TPM-signed update before
FedAvg, and writes signed contribution decisions into the checkpoint lineage.
Its independent verifier recomputes all trust/statistical inputs and the exact
weighted aggregate. The live M6 profile supplies a controlled client that
signs its directionally transformed update. A separate opt-in profile has now completed a fresh
baseline-`1.3` 30-round execution with a genuinely failed Quote appraisal, without relabelling
the counterfactual 2×2 cells as observed trust failures.

## Real post-training Quote failure

The real-failure profile is deliberately separate from the 2×2 policy comparison. All 15
clients first pass M4 and train. In round 30, `client03` extends PCR 10 with the measurement
declared in the signed experiment contract, answers a new one-use challenge, and produces an
authentic AK-signed Quote over the changed PCR state. M4 preserves a signed
`failed_measurement` result. The client then re-signs its unchanged update bundle against that
new appraisal so the live gate can make—and preserve—a real `trust_quarantined` decision before
FedAvg.

The verifier proves both sides of the apparent contradiction: the Quote signature is valid for
the observed PCR values, while the same values do not match the enrolled baseline. It also checks
that every other M5 structural and cryptographic check passes, that the update/metrics bytes are
unchanged across re-attestation, and that the target is absent from the checkpoint's weighted
inputs. The independent verifier passed with zero errors. The campaign contains 450 submissions:
368 full-weight, 75 downweighted, six statistical quarantines, and one real trust quarantine.
The selected round-25 model reaches isolated test macro-F1 `0.935467`; because the failure is in
round 30, the selected metric is a continuity result rather than an estimate of general failure
cost. Full setup and commands are documented in
[`REAL_ATTESTATION_FAILURE.md`](REAL_ATTESTATION_FAILURE.md), and the sanitized evidence is in
[`results/m6-real-attestation-failure-local-test-v1/`](../results/m6-real-attestation-failure-local-test-v1/README.md).

## Forensic explanation of contribution decisions

M7 Integrated Gradients explains why the selected model produced a prediction
for a log window. That method cannot be copied directly onto a client update:
the object being explained here is a model-delta vector plus trust and policy
evidence, not a 25-feature input row. The M6 contribution-explanation bundle
therefore adapts the same provenance and independent-verification principles to
three explanation layers:

1. **policy layer** — the decision status, exact score, quarantine/downweight
   thresholds, signed margins, hard-veto state, and preserved reasons;
2. **statistical/tensor layer** — the contribution of every configured anomaly
   indicator and the named parameter tensors responsible for the largest share
   of squared distance from the candidate coordinate median;
3. **aggregation layer** — the actual mechanism-specific treatment of every
   frozen update.

The aggregation layer deliberately avoids a single generic “selected” label.
FedAvg includes every admitted client with its example-count weight. Clipping
rescales an entire update. Coordinate median selects a value per coordinate and
has no client-level selection set. Trimmed mean removes the `f` lowest and `f`
highest values separately for every coordinate. MultiKrum has a client-level
Krum rank and selected subset. The implemented Bulyan profile first selects
`n-2f` Krum-ranked candidates and then retains `n-4f` closest values per
coordinate.

For every strategy, the explanation code reconstructs the aggregate and checks
it against the existing M6 implementation. The verifier also re-verifies the
joint-admission source, reloads every frozen update by its digest, recomputes
all tensor rankings and traces, and compares the canonical payload bytes.

```bash
fl-forensics m6-explain-contributions \
  --round-workspace artifacts/m5-secure-multiround-local-test-v1/rounds/round-011 \
  --trust-workspace artifacts/m4-trust-local-test-v1 \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --clean-frozen-workspace artifacts/m6-clean-round11-local-test-v1 \
  --clean-comparison-workspace artifacts/m6-clean-round11-local-test-v1-comparison \
  --candidate-frozen-workspace artifacts/m6-malicious-model-replacement-f3-local-test-v1 \
  --candidate-comparison-workspace artifacts/m6-malicious-model-replacement-f3-local-test-v1-comparison \
  --admission-workspace artifacts/m6-joint-admission-model-replacement-matrix-local-test-v2 \
  --admission-config configs/composite-admission.yaml \
  --byzantine-config configs/byzantine-malicious-model-replacement.yaml \
  --config configs/contribution-explanations.yaml \
  --output artifacts/m6-contribution-explanations-model-replacement-local-test-v1

fl-forensics m6-verify-contribution-explanations \
  --round-workspace artifacts/m5-secure-multiround-local-test-v1/rounds/round-011 \
  --trust-workspace artifacts/m4-trust-local-test-v1 \
  --partition-workspace artifacts/m3-data24-parquet-iid-local-test-v1 \
  --clean-frozen-workspace artifacts/m6-clean-round11-local-test-v1 \
  --clean-comparison-workspace artifacts/m6-clean-round11-local-test-v1-comparison \
  --candidate-frozen-workspace artifacts/m6-malicious-model-replacement-f3-local-test-v1 \
  --candidate-comparison-workspace artifacts/m6-malicious-model-replacement-f3-local-test-v1-comparison \
  --admission-workspace artifacts/m6-joint-admission-model-replacement-matrix-local-test-v2 \
  --admission-config configs/composite-admission.yaml \
  --byzantine-config configs/byzantine-malicious-model-replacement.yaml \
  --config configs/contribution-explanations.yaml \
  --workspace artifacts/m6-contribution-explanations-model-replacement-local-test-v1
```

The verified reference contains 15 complete contribution explanations and six
mechanism traces (`l2_clipping` plus the five aggregators). Its manifest is
`9784eb76ce021e653c2b456992ba2d8a00a5bfd832bad95656f1b8596a530243`.
All source, implementation, tensor-attribution, and aggregation-trace checks
pass. The interpretation boundary remains explicit: these explanations show
why the configured mechanisms acted as they did; they do not establish
malicious intent.

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
dispersion, and confidence intervals remain future statistical-validation work
and are not inferred from this deterministic M6 sensitivity analysis. M8
preserves the completed reference chain; it does not add statistical runs.

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

## Independent active-policy trajectories (2026-09-25)

The historical disagreement experiment above deployed only gated_composite. A new
[verified one-seed pilot](../results/m6-active-policy-pilot-v1/README.md) deploys sequential
and gated_composite in separate clean and attacked trajectories. Both reject all 90
controlled unsafe contributions; gated achieves higher test macro-F1 in this seed while
intervening more on benign contributions. This is descriptive, not proof of superiority.
The additional four paired seeds are in progress under the [fixed protocol](M6_POLICY_PILOT.md).
The controlled trust counterfactuals remain distinct from the real PCR-failure experiment.
Historical explanation/M8 accounting profiles remain gated-specific and must not be
used to label sequential trajectories without a separately verified extension.

## Five-seed active-policy gate completed — 2026-09-25

This completion update supersedes the earlier in-progress checkpoints above. All 20
30-round campaigns completed and passed their campaign verifiers (600 rounds, 9,000
contribution decisions). Recovery retained previous artifacts. The final
[report, figures and source-bound tables](../results/m6-active-policy-multiseed-v1/README.md) are available.

Mean test macro-F1: gated/sequential 0.942285/0.939303 clean and
0.939053/0.936771 under controlled disagreement. Paired gated-minus-sequential
95% t intervals include zero in both conditions: [-0.004490, 0.010455] and
[-0.009307, 0.013869]. Superiority is not established. Both exclude 450/450
declared-unsafe contributions per policy, while gated produces more benign
quarantines and downweights. Trust-failure cells remain counterfactual.
Five seed pairs are the statistical units; rounds and contributions are not
independent repetitions. Adaptive attack and threshold/weight sensitivity remain
future gates; the existing M8 closures do not automatically cover these new runs.

## Fixed-signal sensitivity completed — 2026-09-25

[Replay report and figures](../results/m6-policy-sensitivity-replay-v1/README.md): seven predeclared variants across five seeds and
both recorded policy trajectories; 9,000 baseline decisions reproduced and 63,000
variant decisions recomputed. No retraining, test access or configuration selection.
On gated trajectories, downweight threshold +10% reduces clean downweights 366→248
and attacked downweights 196→108 while preserving 450/450 unsafe exclusions.
Quarantine threshold +10% instead retains three unsafe updates at half weight.
These are fixed-signal outcomes, not predictive-performance improvements. Current
policy and frozen experiment inputs are unchanged. Live sensitivity and adaptive
attack validation remain separate future gates.

## Exploratory live sensitivity prepared — 2026-09-25

The [fixed protocol](M6_LIVE_SENSITIVITY.md) tests only the downweight threshold +10% with two
pilot and eight subsequent campaigns, paired against the ten preserved original
gated runs. Config/runner/baseline hashes are frozen; the reference policy is
unchanged. Continuation depends on technical verification, not favorable scores.
Campaign execution is pending. Test results from the standard finalizer will be
exploratory, not independent confirmation after the replay-informed choice.

## Live +10% sensitivity completed — 2026-09-26

Supersedes prior pending recovery notes: all ten new campaigns passed verification.
[Full paired report and four figures](../results/m6-live-downplus10-v1/README.md) compare them with the ten original
gated campaigns. Clean test means: original 0.942285, variant 0.942222; attacked:
0.939053 versus 0.933250. Both paired 95% intervals include zero. Safe downweights
fall 366→242 clean and 196→106 attacked; all 450 unsafe observations per arm remain
excluded in the controlled scenario. The reference remains original gated: the
variant reduces interventions but does not demonstrate predictive improvement.
This replay-motivated experiment is exploratory; adaptive attack validation and
new M7/M8 preservation remain outstanding.

## Adaptive targeted-attack pilot prepared — 2026-09-27

[Threat model, algorithm and execution](M6_ADAPTIVE_ATTACK.md): three colluding clients, targeted
reconnaissance-to-benign gradients over model tensors, projected proposals and exact
gate-feedback backtracking, 66 total queries. Two tests and production source-round
preflight pass, including byte-identical clean aggregation. The search has not yet
run. This privileged white-box frozen-round experiment is not a live signed campaign;
optimization validation is attacker-visible, test access forbidden. No success or
general robustness claim is made. The unexecuted scale-grid draft was superseded.

### Adaptive pilot result — 2026-09-27

The frozen adaptive pilot was executed and independently recomputed (66 queries).
60/64 adaptive proposals were feasible, but selected reconnaissance-to-benign ASR
and ASR gain were both zero. Selected validation macro-F1 decreased by 1.019
percentage points. See `results/m6-adaptive-frozen-pilot-v1/README.md` for all
attempts, figures and limitations. This is not a signed live attack result;
live integration remains in progress.

### Live adaptive smoke independently verified — 2026-09-28

The v2 one-round smoke and independent signed-provenance/search verifier passed.
Three adaptive contributions were newly TPM-signed; actual and predicted aggregates
match exactly. Optimization-validation ASR: 0 to 1; macro-F1: 0.342901 to 0.107455.
This is round 1, one seed, a weak initial baseline and privileged validation access;
no test access or 30-round efficacy claim. See `results/m6-adaptive-live-smoke-v2/README.md`
for figures, all queries and limitations. TPM containers are stopped; evidence is retained.

### Paired adaptive multiround protocol — 2026-09-28

Prepared two 30-round arms at seed 341593: clean and adaptive in rounds 11–30,
66 queries per attacked round, original gated policy. Nine focused tests and
undefined-name checks pass. Test evaluation follows completion of both trajectories.
See `docs/M6_ADAPTIVE_MULTIROUND.md` and `configs/m6-adaptive-paired-s341593-v1.json`.
No multiround attack outcome is claimed before execution and verification.

## Completed paired adaptive v4 — 2026-09-29 analysis

Both 30-round trajectories completed and verified on 2026-09-28 at 18:30 local
(log marker ADAPTIVE PAIRED CAMPAIGN VERIFIED). This supersedes the earlier
running/interrupted status notes, retained above as execution history. The recovery
reverified existing rounds and preserved the original lock. TPMs were stopped by
the completed runner after final verification, not restarted during recovery.

Selected checkpoints: clean round 20, adaptive round 25. Pooled test macro-F1 is
0.9242495921 and 0.9389700250 respectively (adaptive minus clean +1.4720 percentage
points). Targeted reconnaissance-to-benign test ASR is 0/669 for both. None of the
20 adaptive search rounds met the prespecified success criterion (1,320 queries).
All 60 malicious client-round contributions participated: 32 accepted and 28
accepted downweighted. Thus contribution admission is not equivalent to achieving
the attack objective. Honest interventions in rounds 11–30 were 73 downweighted
and 8 quarantined out of 300 clean decisions, versus 47 and 3 out of 240 adaptive
honest decisions; denominators differ and these are descriptive counts.

The first ten paired checkpoints match byte for byte. Selection in the adaptive
arm occurred after attack onset; the zero-ASR finding is not explained by choosing
a pre-attack checkpoint. One seed does not establish statistical superiority,
universal robustness, or a beneficial effect of poisoning. No additional test
inference or post-test tuning was performed for the report.

Report: `results/m6-adaptive-paired-v4/README.md`, source-bound JSON results and four
PNG/PDF figures. Generator: `scripts/report_m6_adaptive_paired_v4.py`. Checks cover
locked files, checkpoint/evaluation/decision hashes, exact pre-attack pairing,
selected query metrics and validation-based checkpoint selection. Existing M8
preservation packages do not yet cover this new experiment. Next: prespecify the
multiseed extension before running it, then extend investigative/preservation
artifacts and thesis discussion. No new experiments were launched by this report.
## Adaptive four-seed extension launched — 2026-09-29

The protocol is fixed in docs/M6_ADAPTIVE_MULTISEED_V1.md and
configs/m6-adaptive-multiseed-v1.lock.json before training. Four new seeds
342593–345593 repeat the unchanged v4 attack and gated-composite defense in paired
clean/adaptive trajectories (240 new rounds, 5,280 search queries). The previously
observed seed 341593 remains explicitly exploratory; no new attack objective or
post-test parameter tuning is included. See the protocol for endpoints and limits.

Runner scripts/run_m6_adaptive_paired_seed.py adds explicit seed-specific federation
and partition checks without changing locked v4 sources. The supervisor
scripts/run_m6_adaptive_multiseed_v1.py uses fresh TPM workspaces and existing M4/M5
commands, verifies immutable inputs and stops on any failed step. Eleven focused
tests and undefined-name checks passed. Live log: m6-adaptive-multiseed-v1.log.
The detached launch receipt is artifacts/m6-adaptive-multiseed-v1-process.json.

All 31 measured M4 image files matched the host. The first preflight probe used
python instead of python3, which is what Dockerfile.m4 provides; it failed before
any network removal or training. After correcting that probe, four historical clean
policy network bridges were inspected and released only after confirming they had
no attached containers or active project containers. Inspection snapshots are under
results/m6-adaptive-multiseed-preflight-v1. All volumes and evidence remain intact.
No new results are claimed until each full pair and final evaluation verify.

## Untargeted adaptive four-seed extension — completed 2026-10-03

Four matched arms (gated-composite clean/adaptive and TPM-only clean/adaptive) completed 30 verified rounds on each of seeds 342593–345593, for 480 secure rounds total. The [published report and comparison figures](../results/m6-adaptive-untargeted-multiseed-v1/README.md) passed manifest and source-receipt checks; the [detailed analysis](M6_ADAPTIVE_UNTARGETED_MULTISEED_RESULTS_V1.md) records per-seed outcomes and limitations.

Mean clean-minus-adaptive selected-checkpoint test macro-F1 loss was 0.000552 for gated-composite and 0.013886 for TPM-only. These are descriptive results, not a significance test or independent-dataset generalization. Seed 342593 was exploratory and its result was known before the other three replications were planned; the TPM-only adaptive checkpoint for that seed was selected at round 10, before the attack began in round 11. The three later seeds show no consistent predictive-performance advantage. Earlier launch and in-progress entries remain historical records; the locked protocol was not changed.
