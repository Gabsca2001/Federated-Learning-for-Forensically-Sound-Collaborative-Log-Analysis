# Admission mass safety: implementation and retrospective validation

The new opt-in guard authorizes or defers original sample-weighted FedAvg. It never restores quarantined mass, alters an existing decision, or manufactures a checkpoint when conditions fail. Production defaults, the measured core, all historical campaigns and the thesis are unchanged. The implementation remains a research adapter, not a completed live TPM integration.

## Exact contract

With authenticated complete eligible counts n_i and actual admission masses m_i, let R=sum(m_i)/sum(n_i) and a_i=m_i/sum(m_i). The joint guard requires at least 10 positive contributors, R>=4/5 and the sum of the three largest a_i<=1/3. Unknown, mismatched or inexact mass/action/count inputs fail explicitly. A mandatory-trust or statistical quarantine keeps m_i=0. When deferred, authorized coefficients and the guarded checkpoint are undefined; computable proposed coefficients remain diagnostic only.
The three-largest sum bounds every subset of at most three nonnegative coefficients by ordering. Interpreting that subset as all attackers additionally assumes at most three authorized adversarial identities. This is not an attacker detector, a Sybil guarantee or a bound on unbounded tensors. When separately composed with fixed tensor clipping, existing fixed-input removal algebra yields 2*A*C per tensor for removed mass A; it does not prove ASR prevention or later recovery.
The 4/5 floor reuses the preceding study's per-round guard. The 1/3 group budget is a conservative declared allocation, not a learned threshold or a robustness theorem. A retention-only control disables the concentration constraint. Both choices are reported without selecting a winner from attack outcomes.

## What was actually validated

- 21 tests passed: 12 new guard tests and 9 existing admission tests. They cover veto preservation, exact policy boundaries, zero/unknown normalization, no re-admission, malformed evidence, tampering, backend suppression and exhaustive subset checks on 50 small populations.
- 2,824 assessments reconstruct two fixed policies on 1,412 verified source rounds from 96 previously observed histories. A separate standard-library checker recomputes ratios, top-k shares, every decision, first deferrals and 64 summary groups.
- 89 actual Flower outputs are repeated at the first/last locally authorized joint-guard rounds, using authenticated original models, decisions and parents. Backend coefficients and checkpoint contents match. In 1,314 deferred assessments, a forbidden numerical callback is demonstrably never invoked.
-No new local training or TPM Quote is produced. No defended ASR is calculated. In particular, later source checkpoints after the first hypothetical deferral cannot be counted as a new guarded continuation.

## Availability result on the preceding severe-tail method

| Cohort | Source mode | Guard | Local deferrals / observed rounds | Uninterrupted compatible histories /3 |
|---|---|---|---:|---:|
| iid | adaptive | retention_and_group_cap | 0/45 | 3 |
| iid | adaptive | retention_only_control | 0/45 | 3 |
| iid | clean | retention_and_group_cap | 0/45 | 3 |
| iid | clean | retention_only_control | 0/45 | 3 |
| iid | complete-trigger | retention_and_group_cap | 16/45 | 1 |
| iid | complete-trigger | retention_only_control | 16/45 | 1 |
| iid | distributed | retention_and_group_cap | 14/45 | 1 |
| iid | distributed | retention_only_control | 14/45 | 1 |
| non-iid | adaptive | retention_and_group_cap | 45/45 | 0 |
| non-iid | adaptive | retention_only_control | 11/45 | 1 |
| non-iid | clean | retention_and_group_cap | 45/45 | 0 |
| non-iid | clean | retention_only_control | 17/45 | 1 |
| non-iid | complete-trigger | retention_and_group_cap | 45/45 | 0 |
| non-iid | complete-trigger | retention_only_control | 12/45 | 1 |
| non-iid | distributed | retention_and_group_cap | 45/45 | 0 |
| non-iid | distributed | retention_only_control | 21/45 | 1 |

The joint guard would defer all 45 observed clean non-IID rounds, and each of those three histories at its first round. It also defers 30 of 90 IID distributed/full-trigger source rounds because their retained nominal mass falls below the floor. These are explicit availability costs, not successful attack prevention. The retention-only guard defers 17 of 45 clean non-IID source rounds and leaves only one of three clean histories uninterrupted.
This confirms that count quorum alone misses substantial influence concentration, while a conservative static coefficient cap is incompatible with the present non-IID sample-weight distribution. Simply forcing admission would invalidate quarantine guarantees. A deployable continuation requires a separately declared support/recovery or aggregation-weight policy and fresh evaluation; this audit does not select or validate that policy.

## Boundaries and reproduction

Trusted clean calibration, complete authenticated rosters/counts, correct callers and appropriate runtime bindings remain assumptions. The module does not authenticate them itself. Robust/geometric-median beta coefficients and tensor transformations have their separate contracts; original FedAvg coefficients are not silently substituted for them. No administrative witness independence, physical TPM protection, general robustness or certified unlearning follows.

```bash
PYTHONPATH=scripts .venv/bin/python -m pytest -q tests/test_admission_mass_safety.py tests/test_composite_admission.py
.venv/bin/python scripts/revision_mass_safety_audit.py
.venv/bin/python scripts/finalize_mass_safety.py
```

Evidence and controllers are versioned in the original WSL repository. Existing audit/publication destinations refuse overwrite. Final closure pins include this independent publisher, input artifacts, guard source and test receipts. The thesis remains frozen.
