# Head-aware CUSUM gate: live study results

Completed 2026-11-10 under the predeclared [protocol](../../../docs/admission-gates/HEAD_CUSUM_STUDY_PROTOCOL.md).
120/120 evaluation cases terminal (117 complete; 3 genuine quorum failures of the
original composite on non-IID assignments). 1,762 rounds independently
reconstructed (head features, CUSUM chain, candidate and original decisions,
masses, FedAvg). Test split opened only after closure and verification
(precommit in `artifacts/.../evaluation/test/precommit-before-test.json`).
Four infrastructure interruptions (WSL memory, full host disk, operator shutdown)
are documented in `artifacts/.../evaluation-interrupted-infrastructure-20261110/`;
affected case directories were preserved unchanged and the deterministic tasks
regenerated; no scientific outcome was discarded.

Generated tables: `cases.csv`, `paired-harm.csv`, `summary.json`
(`scripts/report_head_cusum_study.py`).

## Predeclared decision

| Item | Result |
|---|---|
| Guard (clean, 4 fresh assignments) | passed, 0% benign quarantine |
| Reserved clean guard (6 assignments) | passed: no quorum failure, F1 loss ≤ 2 points |
| **H1** head_cusum < gated_composite paired peak harm (majority) | **not met**: 0 lower, 4 higher, 17 equal, 3 undefined |
| **H2** head_cusum < tpm_only in effective controls (majority) | **met**: 16 lower, 0 higher, 3 equal |
| **H3** head-frozen adaptive: head_cusum vs tpm_only | 5 lower, 0 higher, 1 equal |
| Auxiliary: head_cusum vs head_max | 0 lower, 5 higher, 19 equal |
| Reportable as improved (H1 ∧ H2 ∧ clean guard) | **no** |

## Mean test full-trigger peak ASR (3 assignments per cell; n complete)

| Cohort | Attack | TPM-only | Composite | head_max | head_cusum |
|---|---|---:|---:|---:|---:|
| IID | distributed | 58.6% | 0.0% | 0.0% | 0.0% |
| IID | complete-trigger | 97.9% | 0.0% | 0.0% | 0.0% |
| IID | adaptive | 100.0% | 0.0% | 0.0% | 0.0% |
| IID | adaptive-headfrozen | 100.0% | 0.0% | 0.0% | 0.0% |
| non-IID | distributed | 37.9% | 0.0% (n=1/3) | 37.9% | 37.9% |
| non-IID | complete-trigger | 54.6% | 50.0% (n=2/3) | 54.6% | 54.6% |
| non-IID | adaptive | 66.7% | 31.6% | 37.9% | 41.9% |
| non-IID | adaptive-headfrozen | 66.2% | 32.2% | 37.7% | 37.9% |

Cells with different n are not a fair ranking; failed histories are undefined, never 0%.

## Interpretation

1. **IID:** both head gates eliminate every tested attack (TPM-only reaches 59–100%),
   including the defender-aware and head-frozen adaptive attacks, with no benign
   cost. The original composite does the same here, so H1 records ties, not a gain.
   In the adaptive cells the attackers keep full mass (~20%) yet ASR is 0: the
   defence-aware search can only pick manipulations small enough to pass, which
   are ineffective (containment by constraint, not by exclusion).
2. **Non-IID DBA:** the head gates never trigger; their outcomes are identical to
   TPM-only. The non-IID clean thresholds (fitted on heterogeneous clean histories,
   CUSUM threshold 11.07) are too permissive for small distributed components. The
   composite instead loses quorum in 3/6 DBA histories (undefined outcomes).
3. **Non-IID adaptive:** head gates roughly halve TPM-only harm; the composite is
   lower still (≈32%) but its benign cost is the known quorum fragility.
4. **CUSUM did not help over the per-round max** in live trajectories (5 worse, 0 better),
   unlike the offline replay; the per-round head score carries the benefit.

The candidate is therefore a **robust, low-cost improvement over TPM-only and a
quorum-safe alternative to the composite**, but not a better detector than the
composite under the predeclared criterion, and it gives no protection against
non-IID DBA in this configuration. Thresholds were not changed after any outcome.

## Erratum: duplicated non-IID partition (found 2026-11-10, after this report)

`_dirichlet_assignments` seeds its generator with `seed + attempt`; when attempt 0
of a seed violates the minimum-rows constraint, the retry equals attempt 0 of the
next seed. Non-IID evaluation seeds **2026111024 and 2026111025 received the
identical data partition** (different attacker identities, so the cases differ,
but the data allocation is not independent). The non-IID cohort therefore has
**two distinct partitions, not three**; non-IID cell means overweight one
partition. Conclusions above are unchanged in direction but rest on less
independent evidence than stated. The same defect duplicated earlier non-IID
assignments in `revision-clean-gate-calibration-v1` (2026110613 = …614 fit;
…633 = …634 selection). `src/` is not modified (locked historical studies);
new studies must check partition distinctness at prepare time.

## Limits

Six assignments, one dataset (Data24), test split inspected in earlier work, software
trust assumption (no new TPM Quotes), FedAvg aggregation only. A non-IID-specific
threshold change would be a new development study, not a reinterpretation of this one.
