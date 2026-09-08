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
- [M7 investigation of the M6 disagreement checkpoint](m7-m6-disagreement-investigation-local-test-v1/README.md):
  16 label-independent cases with verified prediction, Integrated Gradients, prototype geometry,
  ATT&CK outcomes, four compact figures, and sanitized bindings to the selected M6 checkpoint.

A snapshot is evidence of a particular completed run. It is not an input to training and is
not a substitute for the complete M8 recovery package. The source report manifests retain
the SHA-256 bindings needed to check that the published report files were copied unchanged.

The repository intentionally does not publish:

- source datasets or reconstructed source records;
- model checkpoints or client updates;
- private keys, TPM state, or client certificates;
- the 2.6 GB offline recovery archive.
