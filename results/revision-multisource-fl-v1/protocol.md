# Protocol: multi-source federated training, leave-one-domain-out (v1)

Written 2026-11-10 before any training for this study. SHA-256 in `protocol.sha256`; the
script refuses to run if it differs. Not edited after results are seen.

## Question

Every earlier model was trained on one network (Data24). In the thesis scenario several
organizations with different networks collaborate. Does a federated model trained on
**several heterogeneous networks**, each normalized to its own benign behaviour,
generalize to a network it has never seen better than (a) the same pipeline trained on one
network and (b) label-free novelty detection on the unseen network?

## Domains (each is one federated client)

| Domain | Units | Baseline (benign reference for normalization and threshold) | Held-out test |
| --- | --- | --- | --- |
| Data24 | global windows (`artifacts/m2-data24-parquet/dataset.json`) | benign windows of the train and validation splits | `split == test` windows |
| Data22 | global windows | 2022-01-09 … 12 | all other dates |
| ToN-IoT | global windows (occurrence view) | 2019-04-02 … 03 | all other dates |
| UNSW-NB15 | source-host × minute units | S0 2015-01-22 14:00–16:00 UTC | all S1 units |

Binary target: benign vs any attack. When a domain is a **training** client it contributes
its training material: Data24 train + validation splits; Data22, ToN-IoT and UNSW-NB15 all
units outside their held-out test (i.e. baseline and, for UNSW-NB15, all S0 units; for
Data22 and ToN-IoT, baseline windows only would contain no attacks, so all their windows are
used). When a domain is **held out**, only its baseline (unlabeled) and test are used.

## Per-client normalization (FedBN-like, label-free)

log1p on the ten count/volume/duration features, then standardization with mean/std of the
domain's own baseline (std < 1e-9 → 1). The same rule is applied to the held-out domain
using its baseline, so no held-out labels are used before evaluation.

## Models and training

Architecture of the Data24 model (25→128→64→32, ReLU) with a binary head, random
initialization (seed). Numerical FedAvg (no TPM/signing pipeline): 30 rounds, every
training client participates each round, 2 local epochs, Adam lr 1e-3 (optimizer state
reset each round), batch 128, class-balanced cross-entropy per client, aggregation weighted
by client sample count. CPU, 4 threads. Seeds 0, 1, 2. The final round is used (no model
selection).

Arms for each held-out domain D:
- **MS-FL:** FedAvg over the three other domains.
- **SS-FL:** same pipeline, Data24 as the only training client (for D = Data24, the
  single source is UNSW-NB15).
- **NOV:** Mahalanobis distance to D's baseline in the same normalized space
  (covariance + 1e-6·I), no training.

## Decision on the held-out domain

Primary (label-free): alert if the score (P(attack) for MS/SS, distance for NOV) exceeds the
99th percentile of scores on D's baseline. Secondary: MS/SS with fixed threshold 0.5.
Metrics: balanced accuracy (primary), FPR, recall, AUROC; mean over seeds.

## Decision rules

Over the four held-out domains:
- **Multi-source helps** if BA(MS) − BA(SS) ≥ 0.05 on at least two domains and ≥ −0.02 on all.
- **Federated knowledge adds value beyond novelty** if BA(MS) − BA(NOV) ≥ 0.03 on at least
  two domains and ≥ −0.02 on all.
- **Equivalent to novelty** if |BA(MS) − BA(NOV)| < 0.03 on at least three domains.
- Otherwise reported as **mixed** for each comparison.

## Limits declared in advance

Four domains with different unit definitions (UNSW-NB15 host units vs global windows),
Argus state mapping for UNSW-NB15, Data22 has only 110 attack windows, period confound on
Data22/ToN-IoT, numerical FedAvg without the secure pipeline, three seeds, correlated units.
