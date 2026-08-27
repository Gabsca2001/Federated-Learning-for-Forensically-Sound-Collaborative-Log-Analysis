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

A snapshot is evidence of a particular completed run. It is not an input to training and is
not a substitute for the complete M8 recovery package. The source report manifests retain
the SHA-256 bindings needed to check that the published report files were copied unchanged.

The repository intentionally does not publish:

- source datasets or reconstructed source records;
- model checkpoints or client updates;
- private keys, TPM state, or client certificates;
- the 2.6 GB offline recovery archive.
