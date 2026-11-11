# Behavioural trigger probe + per-tensor clipping: live study

Completed 2026-11-11. Predeclared protocol (`artifacts/revision-trigger-probe-live/protocol-before-guard.json`,
`e8e911d5…`): unchanged single-feature probe (`scripts/trigger_probe_gate.py`), thresholds =
clean maximum per cohort from verified clean histories (pinned), no fitting in this study.
Fresh Data24 partitions (4 guard, 8 evaluation: 4 IID + 4 Dirichlet 0.3), distinct from all
surviving earlier studies. Attacker data share: IID 20%; non-IID 9–17%.

## Guard (clean, 12 cases, independently verified; revised rule declared beforehand)

All three arms qualified. probe+bounded: **0% honest quarantine on every assignment**, no
consecutive exclusion, F1 loss ≤0.6 points.

## Evaluation (96 cases, all complete, independently reconstructed; test opened after verification)

Mean test full-trigger peak / final ASR (%), 4 assignments per cell:

| Cohort | Attack | TPM+FedAvg | TPM+clipping | **probe+clipping** |
|---|---|---:|---:|---:|
| IID | distributed DBA | 49.0 / 0.0 | 34.0 / 0.0 | **0.0 / 0.0** |
| IID | complete-trigger DBA | 97.6 / 29.7 | 96.5 / 19.9 | **0.0 / 0.0** |
| IID | adaptive | 100.0 / 99.8 | 35.0 / 0.0 | 35.0 / 0.0 |
| non-IID | distributed DBA | 4.1 / 0.0 | 4.3 / 0.0 | **0.0 / 0.0** |
| non-IID | complete-trigger DBA | 54.7 / 5.0 | 53.1 / 7.1 | **0.0 / 0.0** |
| non-IID | adaptive | 99.1 / 70.4 | 43.0 / 0.0 | 43.0 / 0.0 |

## Predeclared hypotheses (paired worst-trigger peak harm, seed = unit)

| Hypothesis | lower | higher | equal | Result |
|---|---:|---:|---:|---|
| P1 probe+clipping vs clipping, all attacks | 16 | 1 | 7 | **holds** |
| P2 same, DBA only | **14** | 0 | 2 | **holds** |
| P3 probe+clipping vs TPM-only FedAvg (effective controls) | **18** | 0 | 0 | **holds** |

Reserved clean assignments: no benign cost for any arm.

## Reading

* **The probe eliminates DBA** (full-trigger ASR 0% at peak and at the end) in IID and non-IID,
  where clipping alone leaves 34–97% peaks; this is the first defence in the project that
  closes the non-IID DBA gap, with zero honest exclusions.
* **Adaptive attacks are contained by clipping**; the probe neither helps nor hurts there
  (identical numbers), consistent with the development finding that adaptive updates show no
  single-feature shortcut. The two layers are complementary.
* Each probe exclusion carries its own evidence (feature and value whose perturbation flips
  attack rows to benign beyond the round's peers).

## Limits

One dataset (Data24, test split inspected in earlier work); 8 evaluation assignments; software
trust assumption (no TPM Quotes). The adaptive attacker optimizes interpolation strength against
the full defence but does not change its trigger design; probe-aware evasion was studied offline
only (`../revision-trigger-probe-dev/`: AND-triggers lose most effect and a pair probe recovers them).
The probe needs a small clean validation set on the server. Non-IID distributed DBA was weak in
these assignments even without defence (≈4% peak).
