# Protocol: Data24 pre-training on unseen ToN-IoT attack families (leave-one-family-out, v1)

Written 2026-11-10 before any training or evaluation for this study. SHA-256 in
`protocol.sha256`; the script refuses to run if it differs. Not edited after results.

## Motivation

`results/revision-label-efficiency-v1` found no benefit from Data24 pre-training, but with a
ceiling effect (16 labels → BA 0.976) because test windows belonged to families seen in
training. Prior knowledge should matter most for **attack families absent from the target
training data**. ToN-IoT windows were examined earlier; this is exploratory, not blind.

## Design

Same windows, family definition, within-family chronological 70/30 split with one-hour
purge, preprocessing (log1p on ten count/volume/duration features, standardization on the
whole training pool without labels), architecture, arms (P: Data24 encoder + new binary
head, three source models paired with seeds; R: random encoder; N: Mahalanobis on labelled
benign windows, 99th-percentile threshold) and training (Adam 1e-3, batch min(32, k),
60 epochs, class-balanced loss, no model selection) as the label-efficiency protocol v1.

For each held-out attack family f ∈ {backdoor, ddos, dos, injection, mitm, password,
ransomware, scanning, xss}:
- **Training pool:** the label-efficiency pool with **every window of family f removed**.
  Preprocessing statistics are recomputed on this reduced pool.
- **Test:** the benign test windows plus **all** windows of family f (pool and test parts).
- Budgets k ∈ {32, 128, all}; seeds {0, 1, 2}; balanced benign/attack sampling as before
  (attack windows drawn only from the remaining families).

## Metrics

Per (f, k, seed, arm): balanced accuracy on benign-test ∪ f (primary), recall on f, FPR on
benign test, AUROC. Summaries: mean over seeds per family, and the macro-mean over the nine
families.

## Decision rules

Let Δ(k) = macro-mean BA(P) − macro-mean BA(R) over families.

- **Pre-training helps on unseen families** if Δ(k) ≥ 0.05 for at least two of the three
  budgets and Δ(k) ≥ −0.02 for all.
- **No benefit** if |Δ(k)| < 0.05 for all three budgets.
- **Pre-training hurts** if Δ(k) ≤ −0.05 for at least two budgets.
- **Mixed** otherwise.

Also reported: number of families where P beats R by ≥ 0.05 at k = all, and how P and R
compare with N (which needs no attack labels and is naturally family-agnostic).

## Limits declared in advance

Single target dataset seen before; families are laboratory campaigns sharing hosts and
dates; benign test windows include the attack-date HTTP minutes; three seeds; correlated
windows.
