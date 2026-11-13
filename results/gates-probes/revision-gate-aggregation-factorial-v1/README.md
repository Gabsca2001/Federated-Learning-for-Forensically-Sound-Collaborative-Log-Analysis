# Gate × aggregation factorial v1: results

Completed 2026-11-10. Protocol `docs/admission-gates/GATE_AGGREGATION_FACTORIAL_PROTOCOL.md`
(frozen `a4d7e78f…`). Analysis declared before the test was opened:
[DECLARATION-BEFORE-TEST.md](DECLARATION-BEFORE-TEST.md).

## Guard (clean only, 36 cases, verified)

Only `tpm_only+fedavg` (reference) and `tpm_only+bounded` qualified:
`gated_composite` lost quorum in non-IID; every `head_cusum` arm kept only 65.7% of
mass in a round because an honest client holding 34% of the data was permanently
quarantined; `tpm_only+trimmed_mean` exceeded the 2-point F1 budget (2.37 points).
The frozen gate hypotheses H1–H4 are therefore not evaluable. Guard non-IID seeds
2026111043/44 had an identical partition (partitioning defect, see erratum in
`../revision-head-cusum-gate-v1/README.md`).

## Evaluation (48 cases, all complete, 720 rounds verified, test opened after verification)

Mean test full-trigger peak / final ASR (3 assignments per cell):

| Cohort | Attack | FedAvg | Bounded (clipping) |
|---|---|---:|---:|
| IID | distributed | 60.9 / 0.0 | 47.2 / 0.0 |
| IID | complete-trigger | 97.9 / 59.4 | 97.3 / 53.4 |
| IID | adaptive | 100.0 / 100.0 | **45.6 / 0.0** |
| non-IID | distributed | 35.9 / 19.0 | 34.8 / 19.0 |
| non-IID | complete-trigger | 61.1 / 45.4 | 60.6 / 35.0 |
| non-IID | adaptive | 96.3 / 69.5 | **53.0 / 33.1** |

**D1** paired worst-trigger peak harm, bounded vs FedAvg: lower in **14/18**, higher
in 0, equal in 4 (all variants); in effective reference controls lower in 13/16,
equal in 3. Clean budgets held on all reserved clean assignments.

## Interpretation

* Clipping is a clear, free improvement against the **adaptive** attack (it caps how
  far a scaled update can move the model) and a modest one against distributed DBA.
  Against the complete-trigger DBA it barely helps: poisoned updates there are not
  larger than benign ones, so a norm bound does not bind.
* It is not a backdoor defence on its own: peaks of 45–97% remain.
* Non-IID seed 2026111035 is unprotected under both operators (100% harm): its three
  attackers hold **42% of the training data**, so no mass-weighted operator without
  detection can contain them. Attacker data share per seed: IID 20%; non-IID 8.7%,
  42.2%, 16.0%.

## Limits

Six assignments, one dataset, software trust assumption. The second D1 line
(effective-only) overwrote the all-variants line in `report/summary.json` because both
shared an identifier; the all-variants count above was recomputed from
`report/paired-harm.csv` (same data).
