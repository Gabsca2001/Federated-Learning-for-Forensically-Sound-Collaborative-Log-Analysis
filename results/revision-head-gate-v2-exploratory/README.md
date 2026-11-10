# Head gate v2: EXPLORATORY live evaluation

Completed 2026-11-10. **Exploratory, not confirmatory.** The frozen v2 protocol
(`artifacts/revision-head-gate-v2/protocol-before-fitting.json`, `c3e6661c…`) let only
TPM-only arms pass the clean guard: head_v2 arms failed the 80% per-round mass budget
through a single borderline false positive (round 14, honest client with 30.7% of the
data, score 6.71 vs threshold 6.56). The deviation (evaluate all arms anyway) was
recorded in the phase protocol (`b45604b9…`) before execution; thresholds, seeds,
attacks and metrics were unchanged.

240 cases (10 distinct assignments, 5 IID + 5 non-IID, partitions checked distinct also
against earlier studies); 236 complete, 4 quorum failures of the original composite.
All 240 independently reconstructed; test opened after verification (precommit).
Attacker data share: IID 20%; non-IID 18.7%, 9.7%, 11.3%, 28.4%, 26.9%.

## Mean test full-trigger peak / final ASR (%)

| Cohort | Attack | TPM+FedAvg | TPM+clip | Composite | head_v2 | head_v2+clip |
|---|---|---:|---:|---:|---:|---:|
| IID | distributed | 53.4 / 2.6 | 32.1 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| IID | complete-trigger | 97.6 / 52.7 | 96.2 / 45.7 | 0 / 0 | 0 / 0 | 0 / 0 |
| IID | adaptive | 100 / 100 | 35.8 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| IID | adaptive, head frozen | 100 / 74.1 | 6.2 / 0 | – | 0 / 0 | 0 / 0 |
| non-IID | distributed | 38.6 / 2.8 | 34.3 / 0 | 0 / 0 (3/5) | 38.6 / 2.8 | 34.3 / 0 |
| non-IID | complete-trigger | 56.3 / 32.4 | 56.2 / 24.2 | 0 / 0 | 56.3 / 32.4 | 56.2 / 24.2 |
| non-IID | adaptive | 87.8 / 59.2 | 53.8 / 0 | 4.6 / 1.3 (4/5) | 58.4 / 36.6 | 39.9 / 0.1 |
| non-IID | adaptive, head frozen | 81.8 / 44.1 | 33.3 / 0.3 | – | 59.9 / 43.6 | 34.0 / 3.2 |

## Paired worst-trigger peak harm (exploratory hypothesis checks)

| Comparison | lower | higher | equal | undefined |
|---|---:|---:|---:|---:|
| H1 head_v2+clip vs TPM+clip | 24 | 2 | 14 | 0 |
| H2 head_v2 vs TPM+FedAvg (effective controls) | 23 | 0 | 10 | 0 |
| H3 head_v2 vs original composite | 0 | 9 | 17 | 4 |
| H4 head frozen: head_v2+clip vs TPM+clip | 6 | 2 | 2 | 0 |

Benign cost on the 10 reserved clean assignments: every head_v2 and TPM arm within
budget (quarantine ≤5%, F1 loss ≤2 points, no quorum failure). The original composite
failed on 6/10: benign quarantine 10–26% in non-IID, clean F1 loss up to 9.3 points,
one clean quorum failure.

## Reading

1. **IID: head_v2 removes every tested attack**, including the defender-aware and
   head-frozen adaptive attacks, at no benign cost. Clipping alone leaves 6–96% peaks.
2. **Non-IID DBA: head_v2 never triggers**; outcomes equal the TPM arms. Distributed
   poisoning in heterogeneous data is not separable by these indicators.
3. **Non-IID adaptive: the two layers add up.** head_v2 alone 58%, clipping alone 54%,
   both 40% peak (final ≈ 0%). This is the complementarity the factorial was built to test.
4. **The original composite has the lowest attack numbers but is not usable as is**:
   in non-IID it excludes 10–26% of honest clients, loses up to 9 F1 points and loses
   quorum in 4 attacked and 1 clean history. Its zero ASR partly reflects excluding
   most of the federation.
5. **Head-frozen evasion** reduces but does not remove head_v2's benefit (H4 6/2/2).

Recommended configuration for the thesis (exploratory evidence): **head_v2 + per-tensor
clipping** — no benign cost, complete containment in IID, additive containment of
adaptive attacks in non-IID; non-IID DBA remains an open limitation.

## Limits

Exploratory status (guard not passed); one dataset (Data24; test split inspected in
earlier work); 10 assignments; software trust assumption (no TPM Quotes).
