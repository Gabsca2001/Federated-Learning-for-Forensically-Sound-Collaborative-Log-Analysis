# Label efficiency on ToN-IoT: Data24 pre-training vs scratch

Question: does an encoder pre-trained with FedAvg on Data24 reach good ToN-IoT performance
with fewer labelled windows than the same network trained from scratch?
`protocol.md` (SHA-256 `27645349…`) fixed split, budgets, arms, training and decision rules
before any training. ToN-IoT windows were examined in earlier studies, so this is an
exploratory assessment, not a blind test.

Setup: within-family chronological 70/30 split with a one-hour purge (pool 5,008 windows;
test 2,380 = 866 benign + 1,514 attack); log1p + pool standardization without labels;
budgets 16–512 and all, three seeds; P = Data24 encoder (three different source models) +
new binary head, R = random encoder, both fine-tuned identically (60 epochs, no model
selection); N = Mahalanobis novelty on the labelled benign windows.

## Results (test balanced accuracy, mean ± SD over three seeds)

| Labelled windows | P (pre-trained) | R (scratch) | N (novelty) | Δ = P − R |
| ---: | ---: | ---: | ---: | ---: |
| 16 | 0.974 ± 0.002 | 0.976 ± 0.003 | 0.500 | −0.003 |
| 32 | 0.976 ± 0.003 | 0.979 ± 0.004 | 0.518 | −0.003 |
| 64 | 0.974 ± 0.001 | 0.979 ± 0.001 | 0.771 | −0.005 |
| 128 | 0.944 ± 0.030 | 0.944 ± 0.032 | 0.883 | +0.000 |
| 256 | 0.950 ± 0.024 | 0.948 ± 0.025 | 0.915 | +0.002 |
| 512 | 0.935 ± 0.008 | 0.930 ± 0.007 | 0.923 | +0.005 |
| all (5,008) | 0.927 ± 0.001 | 0.928 ± 0.000 | 0.926 | −0.000 |

**Protocol outcome: `no_benefit`.** Both P and R reach BA ≥ 0.80 with 16 labelled windows;
N needs 128.

## Reading

1. **No measurable benefit from Data24 pre-training.** P and R differ by at most 0.005 at
   every budget, with every source model.
2. **The outcome is a ceiling effect, so it is weak evidence.** Sixteen labelled windows
   trained from scratch already give BA 0.976. Within-family chronological splits keep test
   windows very close to training windows of the same family (dates are interleaved across
   families and laboratory hosts are shared), so this split leaves no room for any prior
   knowledge to help. The experiment cannot distinguish "pre-training does not help" from
   "the task is too easy to show it".
3. **More labels slightly reduce BA** (0.976 at 16 → 0.927 with all). Balanced small subsets
   versus the imbalanced full pool, and more varied benign windows, are plausible causes;
   they were not investigated, and no setting was changed after seeing this.
4. **Supervised labels matter more than novelty.** With few labels, a supervised head on 16
   windows clearly beats benign-only novelty, which needs about 128 benign windows to
   approach the same level.

## Consequence

Together with the frozen-transfer, robust-preprocessing and baseline-adaptation controls,
no experiment shows that what the federated model learned on Data24 adds value on
ToN-IoT. This experiment does not refute a benefit in harder settings (unseen families,
host-disjoint or truly future test periods), where a ceiling would not hide it.

```bash
.venv/bin/python scripts/label_efficiency.py   # refuses if protocol digest differs
```
