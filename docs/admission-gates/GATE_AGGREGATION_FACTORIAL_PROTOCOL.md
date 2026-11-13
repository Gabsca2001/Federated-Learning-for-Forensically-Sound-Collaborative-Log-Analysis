# Gate × aggregation factorial: predeclared study

Drafted 2026-11-10. **Code written and unit-tested; not yet prepared or run.**
`prepare` will freeze this protocol and its source locks; it is scheduled after
the [head-CUSUM evaluation](HEAD_CUSUM_STUDY_PROTOCOL.md) closes so that the two
studies do not compete for WSL memory. Deployed defaults and the thesis are unchanged.

## Question

Admission gates and robust aggregation do different jobs. The gate *detects and
attributes* (per-client, explainable decisions). The aggregation operator *limits
influence* without detecting anything. Earlier studies tested them separately, and
two known interactions can make combinations worse: downweighting benign clients
raised the attacker share in 17/80 attack rounds, and coefficient capping
redistributed weight to attackers in 90/180 attack rounds. This study measures
whether the layers are complementary against DBA and adaptive attackers who know
the **complete** defence.

## Arms

| Gate \ operator | `fedavg` | `bounded` | `trimmed_mean` |
|---|---|---|---|
| `tpm_only` | reference | clipping only | robust only |
| `gated_composite` | original gate | original + clipping | original + robust |
| `head_cusum` | candidate gate | **candidate pair** | candidate + robust |

- `fedavg`: unchanged Flower sample-weighted FedAvg over the gate's masses.
- `bounded`: per-tensor L2 clipping to fixed clean 99th-percentile limits from
  3,675 clean updates (`revision-bounded-influence-v1`), then the gate's masses.
- `trimmed_mean`: unweighted coordinate-wise trimmed mean, f = 3 per side, over
  gate-retained clients. Downweighted clients enter unweighted; `n ≤ 2f` is an
  availability failure. Influence is measured as each client's share of retained
  coordinate values.
- `head_cusum` reuses the pinned head-CUSUM model and thresholds unchanged.
- Quorum: ten positive-mass contributors for every operator.

Code: `scripts/factorial_aggregators.py` (operators, influence),
`scripts/revision_gate_aggregation_factorial.py` (controller, adapters),
`tests/test_factorial_aggregators.py` (equivalence with the existing
`aggregate_deltas` trimmed mean, quarantine exclusion, precondition failure,
clipping, FedAvg equivalence without clipping).

## Stages

| Stage | Cases | Content |
|---|---:|---|
| guard | 36 | 4 fresh clean assignments (2 IID, 2 non-IID) × 9 arms |
| evaluation | ≤ 234 | 6 fresh reserved assignments × qualified arms × {clean, distributed, complete-trigger, adaptive}, plus `adaptive-headfrozen` for the 3 `head_cusum` arms |

Guard rule (clean only): an arm is evaluated only if on every guard assignment it
completes 15 rounds, quarantine ≤ 5%, pooled nominal mass ≥ 90%, every round
≥ 80%, and validation macro-F1 loss vs paired `tpm_only+fedavg` ≤ 2 points at
rounds 10/15. The reference arm is always evaluated. No change after outcomes.

Seeds: guard 2026111041–44, evaluation 2026111031–36, disjoint from every earlier
gate study (checked at prepare time). Attacks: 15 rounds, attack in rounds 1–10,
50% poisoning at three clients, unchanged triggers and six-alpha search. The
adaptive objective is scored after the complete defence of each arm (gate
decisions, CUSUM state, operator); ties prefer larger manipulation.

## Hypotheses

- **H1 complementarity:** `head_cusum+bounded` has lower paired worst-trigger peak
  harm than both single-layer arms (`head_cusum+fedavg`, `tpm_only+bounded`) in a
  majority of defined attacked comparisons.
- **H2 DBA and adaptive:** `head_cusum+bounded` reduces paired peak harm vs
  `tpm_only+fedavg` in effective controls (≥ 20 point ASR increase, ≤ 5 point
  clean F1 loss), for distributed, complete-trigger and adaptive attacks.
- **H3 interactions (reported, not tuned):** attacker influence after
  normalization vs the reference arm; whether Composite downweighting or
  trimmed-mean selection increases attacker influence; availability failures.
- **H4 robustness:** under `adaptive-headfrozen`, whether `head_cusum+bounded`
  keeps any benefit over `tpm_only+bounded`.

Endpoints: paired worst-trigger peak harm, full/component-trigger peak and final
ASR, clean macro-F1 at rounds 10/15, attacker influence, failures (undefined,
never ASR 0), detection round, runtime per layer. Seed/partition assignment is the
repetition unit; one dataset (Data24); the test split was inspected before.

## Commands (after the head-CUSUM evaluation closes)

```bash
.venv/bin/python scripts/revision_gate_aggregation_factorial.py prepare --lab <scratch>/lab
.venv/bin/python scripts/revision_gate_aggregation_factorial.py smoke --lab <scratch>/lab --smoke-dir <scratch>/smoke
.venv/bin/python scripts/revision_gate_aggregation_factorial.py prepare
.venv/bin/python scripts/revision_gate_aggregation_factorial.py guard --workers 2
.venv/bin/python scripts/revision_gate_aggregation_factorial.py guard-decide
.venv/bin/python scripts/revision_gate_aggregation_factorial.py evaluation --workers 2
```

A verifier extension (operator reconstruction for `bounded` and `trimmed_mean`),
the test-phase evaluator and the report must exist before opening the test split.
