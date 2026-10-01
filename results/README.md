# Published result snapshots

This directory contains small, sanitized result snapshots intended for direct inspection on
GitHub. It is distinct from `artifacts/`, which remains ignored because it contains generated
evidence, models, private trust state, and large recovery packages.

## Available snapshot

- [M3 paired multi-seed v2](m3-multiseed-v2/README.md): five verified paired IID/non-IID
  FedAvg repetitions, confidence intervals, client-local comparisons, and a compact figure.
- [Reference local-test v1](reference-local-test-v1/README.md): selected M5 learning metrics
  and figures, the six-case M7 investigation report, and the final M8 verification receipt.
- [M4–M8 offline overhead v1](overhead-local-test-v1/README.md): 13 verified warm-process
  stages, raw summary statistics, compact CSV, receipt, and logarithmic latency figure.
- [M4–M5 containerized runtime overhead v1](runtime-overhead-local-test-v1/README.md): three
  fresh 15-`swtpm` trials, mTLS/Quote/ESK and secure-round timings, compact CSVs, receipt, and
  runtime latency figure.
- [M5 external Data22 generalization v1](m5-external-generalization-local-test-v1/README.md):
  verified binary/shared-label transfer metrics, confusion matrices, feature-shift evidence,
  and a two-burst Discovery window-alignment stress test.
- [M5 in-round composite campaign v1](m5-in-round-composite-local-test-v1/README.md): verified
  30-round TPM/statistical admission over newly trained contributions, selected-checkpoint
  metrics, and clean-run intervention explanations by round, client, scalar indicator, named
  model tensor, policy counterfactual, and effective aggregation influence.
- [M6 joint TPM/statistical admission v1](m6-composite-admission-local-test-v1/README.md):
  clean-calibrated policy comparison, per-client risk/status table, and controlled 2x2
  trust/statistics disagreement matrix.
- [M6 contribution-decision explanations v1](m6-contribution-explanations-local-test-v1/README.md):
  per-client policy/tensor drivers plus clipping, trimmed-mean, MultiKrum, and Bulyan treatment
  traces reconstructed from the same frozen updates.
- [M6 live TPM/statistical disagreement v1](m6-trust-statistical-disagreement-local-test-v1/README.md):
  verified 30-round training-time 2x2 disagreement experiment, paired policy outcomes, safe
  intervention costs, selected-model utility, and sanitized source bindings.
- [M6 live contribution-decision explanations v1](m6-live-contribution-explanations-local-test-v1/README.md):
  independently verified explanations for all 450 deployed training decisions, including exact
  policy margins, named tensor drivers, retained FedAvg weight, aggregate influence, deterministic
  cases, and sanitized provenance bindings.
- [M4/M6 real post-training TPM failure v1](m6-real-attestation-failure-local-test-v1/README.md):
  authentic non-conforming `swtpm` Quote, signed failed appraisal, fail-closed contribution
  decision, zero-weight FedAvg exclusion, paired clean effects, and all 450 sanitized outcomes.
- [M7 investigation of the M6 disagreement checkpoint](m7-m6-disagreement-investigation-local-test-v1/README.md):
  16 label-independent cases with verified prediction, Integrated Gradients, prototype geometry,
  ATT&CK outcomes, four compact figures, and sanitized bindings to the selected M6 checkpoint.
- [M8 closure of the M6 disagreement experiment](m8-m6-disagreement-preservation-local-test-v1/README.md):
  final offline-verified M6→M7→M8 lineage, thesis-oriented metrics, per-policy/round/client
  accounting, canonical receipt, cryptographic bindings, and two compact figures.

A snapshot is evidence of a particular completed run. It is not an input to training and is
not a substitute for the complete M8 recovery package. The source report manifests retain
the SHA-256 bindings needed to check that the published report files were copied unchanged.

The repository intentionally does not publish:

- source datasets or reconstructed source records;
- model checkpoints or client updates;
- private keys, TPM state, or client certificates;
- the 2.6 GB offline recovery archive.

## Additional completed research snapshots (status 2026-09-29)

- [Active-policy pilot](m6-active-policy-pilot-v1/README.md): initial paired policy runs.
- [Five-seed active-policy comparison](m6-active-policy-multiseed-v1/README.md): 20 verified campaigns; paired intervals include zero.
- [Fixed-signal sensitivity](m6-policy-sensitivity-replay-v1/README.md): seven variants, replay only.
- [Live +10% downweight sensitivity](m6-live-downplus10-v1/README.md): ten new campaigns; reference policy retained.
- [Frozen adaptive pilot](m6-adaptive-frozen-pilot-v1/README.md): no targeted success within the fixed 66-query budget.
- [Signed adaptive smoke](m6-adaptive-live-smoke-v2/README.md): round-1 validation success; not a mature-model/test result.
- [Paired adaptive v4](m6-adaptive-paired-v4/README.md): 60 verified rounds; selected-checkpoint test ASR 0/669 in both arms.
- [Numerical runtime preflight](m6-numeric-runtime-preflight-v1/summary.json): 36 independent container probes.
- [Preserved v3 numerical incident](m6-adaptive-paired-v3-reproducibility-incident/diagnosis.json): stopped before adaptive treatment and test evaluation.

These are dated snapshots. Their future-work paragraphs describe what remained at
publication time; the index above and current protocol documentation describe today's
status. Snapshot files with recorded hashes are not retroactively rewritten.
The [four-new-seed extension](../docs/M6_ADAPTIVE_MULTISEED_V1.md) is running, not a
completed result. Raw Docker network inspection from its preflight is local operational
material and is excluded from publication. The existing M8 snapshots do not cover
these newer extensions. No private keys, full updates or dataset records are published.

## Adaptive extension completed — 2026-09-30

[Five-seed paired analysis](m6-adaptive-multiseed-v1/README.md): all four new pairs verified; prior in-progress notes above are historical. Includes per-seed outcomes, separate four-new-seed statistics, four PNG/PDF figures, data and source/output hashes. No new model inference. This extension is not yet covered by an M8 recovery package.

## Adaptive objective and policy ablation — 2026-09-30

[Four-cell frozen-round pilot](m6-adaptive-objectives-ablation-v1/README.md), independently recomputed. The untargeted objective finds a 25.297 pp validation macro-F1 reduction under TPM-only and 0.675 pp under gated-composite. The result is validation-selected on one frozen round; it motivates, but does not replace, a new signed live multi-seed experiment.
