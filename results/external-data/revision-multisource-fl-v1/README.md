# Multi-source federated training, leave-one-domain-out

Question: does a federated model trained on **several heterogeneous networks** (each a
client, each normalized to its own benign baseline, FedBN-like) generalize to an unseen
network better than a single-source model and than label-free novelty detection there?
`protocol.md` (SHA-256 `2a94343c…`) fixed domains, splits, training and rules before any
training. Numerical FedAvg (30 rounds, 2 local epochs, binary head, final round, no model
selection), three seeds; label-free decision: alert above the 99th percentile of scores on
the held-out domain's baseline.

## Results (held-out balanced accuracy, mean of three seeds)

| Held-out domain | MS-FL (other three) | SS-FL (one source) | NOV (Mahalanobis) | MS-FL @ 0.5 | MS FPR / recall / AUROC |
| --- | ---: | ---: | ---: | ---: | --- |
| Data24 | 0.709 | 0.500 | **0.993** | 0.758 | 0.011 / 0.429 / 0.629 |
| Data22 | 0.520 | 0.491 | **0.998** | 0.524 | 0.014 / 0.055 / 0.056 |
| ToN-IoT | 0.680 | 0.505 | **0.895** | 0.717 | 0.134 / 0.493 / 0.705 |
| UNSW-NB15 | 0.770 | 0.699 | **0.954** | 0.500 | 0.014 / 0.555 / 0.749 |

Per-seed MS-FL BA: Data24 0.821 / 0.500 / 0.805; ToN-IoT 0.655 / 0.710 / 0.674;
UNSW-NB15 0.759 / 0.755 / 0.797.

Δ(MS − SS): +0.209, +0.030, +0.174, +0.072 → **`multi_source_helps`**.
Δ(MS − NOV): −0.284, −0.477, −0.215, −0.184 → rule label `mixed`; in substance MS-FL is
**worse than novelty on all four domains** by 0.18–0.48 (the protocol defined no explicit
"worse" category for this comparison; the numbers are reported as they are).

## Reading

1. **Federating several networks helps relative to one network.** On every held-out domain
   the multi-source model beats the single-source model, by up to 0.21 BA; single-source
   models are mostly at chance on unseen networks.
2. **It still does not generalize well enough.** Recall on unseen networks stays at
   6–56%, AUROC 0.06–0.75, and one seed collapses on Data24. On Data22 the ranking is
   inverted (AUROC 0.056): what the other networks call attack-like is the opposite of
   Data22's reconnaissance traffic.
3. **Label-free novelty on the unseen network dominates every trained model**, as in all
   earlier studies (BA 0.90–1.00), including UNSW-NB15 where benign and attack units share
   the same minutes.

## Consequence

Multi-source federation is the first trained configuration that improves generalization in
a consistent direction, which supports the thesis scenario of collaboration across
organizations. However, with four networks of very different traffic, the learned decision
function remains far below a baseline-relative novelty detector on the network it has not
seen. The practical recommendation is to pair federated classifiers with per-site
benign-baseline detection rather than to rely on transfer of the classifier alone.

Limits: different unit definitions across domains, Argus mapping for UNSW-NB15, period
confound on Data22/ToN-IoT, Data22 with 110 attack windows, numerical FedAvg without the
secure pipeline, three seeds, no significance testing.

```bash
.venv/bin/python scripts/multisource_fl.py   # refuses if protocol digest differs
```
