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

## Adaptive-attack results: how to read them

"Adaptive" means that the attacker uses feedback from a declared validation objective and admission policy to shape candidate updates. The experiments below answer different questions; do not compare their headline metrics as if they measured the same attack.

There are two objectives:

- **Targeted reconnaissance-to-benign:** count true reconnaissance examples classified as benign. Targeted ASR is this count divided by the number of true reconnaissance examples.
- **Untargeted degradation:** reduce overall validation macro-F1 without targeting one class.

Keep three outcomes separate:

1. **Search success**: the optimizer found a candidate satisfying its predeclared validation criterion. The attacker sees that validation feedback, so this is not a held-out attack-success rate.
2. **Admission**: whether a malicious contribution was accepted, downweighted, or quarantined. Admission is not attack success, and an intervention is not proof the attack was detected or stopped.
3. **Selected-checkpoint test performance**: the clean and adaptive trajectories after checkpoint selection. This is the held-out predictive endpoint, but it does not identify which update caused a change.

### Targeted reconnaissance-to-benign experiments

- [Frozen pilot](m6-adaptive-frozen-pilot-v1/README.md): one frozen round and 66 validation-oracle queries. Targeted ASR stayed at zero, although the selected candidate reduced validation macro-F1 by 1.019 percentage points. This is a finite-search negative result, not a live trajectory or test evaluation.
- [Signed live smoke](m6-adaptive-live-smoke-v2/README.md): one live round with three newly TPM-signed malicious updates. Validation ASR rose from 0 to 1 on the initial model. This confirms the signing/admission path for an adaptive proposal; the starting model was weak and no test set or mature model was evaluated.
- [Paired adaptive v4](m6-adaptive-paired-v4/README.md): one seed, matched clean and targeted-adaptive runs of 30 rounds each, with attack from round 11. Selected test ASR was 0/669 in both arms, and no attacked round met the validation success threshold. This objective did not succeed in this run; that does not mean there were no other classification errors.
- [Targeted five-seed extension](m6-adaptive-multiseed-v1/README.md): five paired seeds and 300 rounds overall. Selected test ASR remained 0/669 in both arms for every seed. Mean adaptive-minus-clean test macro-F1 difference was +0.4038 percentage points. This is descriptive evidence from a small number of seeds on the same dataset, not a significance test or proof of general robustness.

### Untargeted all-class degradation experiments

- [Objective/policy frozen pilot](m6-adaptive-objectives-ablation-v1/README.md): targeted and untargeted searches under gated-composite and TPM-only, with one signed round and 66 queries per cell. For the untargeted objective, validation degradation was 0.675 points with gated-composite and 25.297 points with TPM-only. This shows that the statistical filter constrained this finite validation search on this particular round. No test data or live multiround training were used; TPM-only still retains TPM trust and signature checks.
- [Untargeted live four-seed extension](m6-adaptive-untargeted-multiseed-v1/README.md): four seeds, four matched arms per seed, 30 rounds per arm, and attacks in rounds 11-30. This is the latest live experiment and the most relevant result for the untargeted objective.

### What the latest live result says

The four arms are gated-composite clean/adaptive and TPM-only clean/adaptive: 480 verified secure rounds in total. "TPM-only" removes the statistical admission gate; TPM trust and signature checks remain.

For each policy there are 80 attacked rounds. Search success means finding a proposal with at least 0.01 absolute validation macro-F1 loss against that round's clean control. It occurred in 5/80 gated-composite rounds and 46/80 TPM-only rounds. This is a **validation-search result**, not test ASR. The difference is consistent with the statistical gate limiting proposals that meet the exposed validation objective.

Admission is a separate result. Across 240 malicious client-round contributions in gated adaptive arms, 105 were accepted at full weight, 124 were downweighted, and 11 were quarantined. All 240 matched TPM-only contributions were accepted. These counts describe policy treatment; they do not mean that 105 attacks succeeded or that 11 were detected.

For selected-checkpoint test performance, loss is clean macro-F1 minus adaptive macro-F1, so positive means the adaptive checkpoint scored lower. The four-seed means are +0.000552 for gated-composite and +0.013886 for TPM-only. However, the TPM-only adaptive checkpoint for seed 342593 was selected at round 10, before the attack began in round 11; it is not a poisoned selected checkpoint. Across the three additional seeds alone, mean losses are nearly equal: +0.000674 gated-composite and +0.000734 TPM-only. The test averages therefore show no consistent replicated advantage for either policy.

Post-attack validation trajectories show a much larger gap under TPM-only than under gated-composite, but the attacker search and checkpoint selection both use that same validation signal. Treat this as a descriptive mechanism check, not an independent endpoint or significance result. The four seeds use UWF-ZeekData24 with different training/partition seeds; they are not four independent datasets. See the [full interpretation and per-seed table](../docs/M6_ADAPTIVE_UNTARGETED_MULTISEED_RESULTS_V1.md), then inspect the linked CSVs and figures before quoting a summary number.

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
The earlier running note for the targeted four-new-seed extension is historical and is
superseded by the completion entry below. Raw Docker network inspection is local operational
material and is excluded from publication. The existing M8 snapshots do not cover
these newer extensions. No private keys, full updates or dataset records are published.

## Follow-ups to recommendations in dated snapshots

The report READMEs below preserve their original wording because published manifests bind their bytes. Use this status map for work completed after those snapshots:

- The five-seed active-policy reports proposed threshold sensitivity and adaptive testing. Follow-ups include the [fixed-signal sensitivity replay](m6-policy-sensitivity-replay-v1/README.md), the [live +10% downweight campaign](m6-live-downplus10-v1/README.md), and the adaptive campaigns summarized above. The original gated-composite policy remains the reference.
- The frozen targeted pilot and signed smoke called for a paired multiround evaluation. That work is recorded in [paired adaptive v4](m6-adaptive-paired-v4/README.md) and the [five-seed targeted extension](m6-adaptive-multiseed-v1/README.md). The selected test targeted ASR stayed at 0/669; this targeted finding does not apply to the different untargeted objective.
- The [objective/policy frozen pilot](m6-adaptive-objectives-ablation-v1/README.md) proposed a live multiseed untargeted evaluation. That follow-up is complete in the [four-seed live report](m6-adaptive-untargeted-multiseed-v1/README.md); treat it as descriptive, not a significance test.
- In the [M8 closure report](m8-m6-disagreement-preservation-local-test-v1/README.md), M8.1-M8.5 are the five assurance stages; M8.6 is the final-lineage verification that closes the chain.

## Adaptive extension completed — 2026-09-30

[Five-seed paired analysis](m6-adaptive-multiseed-v1/README.md): all four new pairs verified; prior in-progress notes above are historical. Includes per-seed outcomes, separate four-new-seed statistics, four PNG/PDF figures, data and source/output hashes. No new model inference. This extension is not yet covered by an M8 recovery package.

## Adaptive objective and policy ablation — 2026-09-30

[Four-cell frozen-round pilot](m6-adaptive-objectives-ablation-v1/README.md), independently recomputed. The untargeted objective finds a 25.297 pp validation macro-F1 reduction under TPM-only and 0.675 pp under gated-composite. The result is validation-selected on one frozen round; it motivates, but does not replace, a new signed live multi-seed experiment.


## Untargeted live adaptive extension — completed 2026-10-03

[Four-seed report and figures](m6-adaptive-untargeted-multiseed-v1/README.md):
seeds 342593–345593 completed and verified four matched 30-round arms each.
The report includes paired selected-checkpoint test losses, search success by
policy and seed, admission counts with denominators, three PNG comparisons, and
source-lock/completion receipts. Results are descriptive on one dataset; the
342593 TPM-only adaptive checkpoint predates attack onset and strongly affects
its aggregate mean. See the [detailed interpretation](../docs/M6_ADAPTIVE_UNTARGETED_MULTISEED_RESULTS_V1.md).
