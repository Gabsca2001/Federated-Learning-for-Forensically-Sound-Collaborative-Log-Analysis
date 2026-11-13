# Leave-one-family-out: Data24 pre-training on unseen ToN-IoT attack families

Follow-up to `results/external-data/revision-label-efficiency-v1`, whose test contained only families seen
in training (ceiling effect). Here each of the nine attack families is removed entirely from
the training pool and used as the attack part of the test, with the benign test windows.
`protocol.md` (SHA-256 `11eb1fd7…`) fixed every setting before training; arms, training and
preprocessing are identical to the label-efficiency study. Exploratory (ToN-IoT seen before).

## Results

Balanced accuracy on benign test ∪ held-out family, mean of three seeds, k = all labels:

| Held-out family | P (Data24 encoder) | R (scratch) | N (novelty) | Family recall P / R / N |
| --- | ---: | ---: | ---: | --- |
| backdoor | 0.931 | 0.931 | 0.926 | 0.999 / 1.000 / 1.000 |
| ddos | 0.924 | 0.925 | 0.926 | 0.984 / 0.988 / 1.000 |
| dos | 0.932 | 0.931 | 0.926 | 1.000 / 1.000 / 1.000 |
| injection | 0.932 | 0.932 | 0.926 | 1.000 / 1.000 / 1.000 |
| mitm | 0.857 | 0.866 | 0.926 | 0.846 / 0.866 / 1.000 |
| password | 0.931 | 0.931 | 0.926 | 0.998 / 1.000 / 1.000 |
| ransomware | 0.841 | 0.832 | 0.926 | 0.814 / 0.796 / 1.000 |
| scanning | 0.912 | 0.913 | 0.926 | 0.960 / 0.963 / 1.000 |
| xss | 0.932 | 0.931 | 0.926 | 1.000 / 1.000 / 1.000 |

Macro-mean BA over families: k=32 P 0.934 / R 0.935 / N 0.518; k=128 P 0.921 / R 0.914 /
N 0.883; k=all P 0.910 / R 0.910 / N 0.926.

**Protocol outcome: `no_benefit`** (|Δ| ≤ 0.006 at every budget; P beats R by ≥ 0.05 on
zero families).

## Reading

1. **Data24 pre-training gives no advantage even on unseen families.** P and R track each
   other within 0.01 on every family and budget.
2. **The ceiling persists.** Unseen families are still detected at 96–100% recall by both
   arms except MITM and ransomware (≈80–87%). The limiting factor of balanced accuracy is the
   benign false-positive rate (≈0.13–0.15), not attack recognition. ToN-IoT attack minutes
   differ so strongly from benign minutes (median 2,217 vs 65 connections) that any family
   is separable once a few attacks of other families are labelled.
3. **Novelty wins where supervision lacks the family.** On the two hardest families (MITM,
   ransomware) the benign-only Mahalanobis detector (recall 1.00) outperforms both
   supervised arms, at the same benign FPR.

## Consequence

ToN-IoT cannot reveal a benefit from Data24 pre-training: its attacks are too easy to
separate within the dataset, and the residual errors are benign false alarms. Across all
generalization studies (frozen transfer, scale-robust preprocessing, baseline adaptation
with controls, label efficiency, leave-one-family-out), no evidence shows that knowledge
learned on Data24 adds value on ToN-IoT. Whether it would on a harder target (low-volume,
tactic-level attacks mixed with benign traffic in the same period) remains untested.

```bash
.venv/bin/python scripts/label_efficiency_lofo.py   # refuses if protocol digest differs
```
