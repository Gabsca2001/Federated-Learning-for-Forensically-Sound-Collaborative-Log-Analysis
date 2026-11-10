# Tensor-derived admission indicators (exploratory, offline)

Completed 2026-11-10. Follows the
[non-compensatory replay](../revision-noncompensatory-replay-v1/README.md), which
showed that the five deployed indicators cap any combination rule at AUC about
0.82–0.85. This study computes **new indicators from the retained client update
tensors** and evaluates them with a development/holdout seed split. No training,
no test inference, no change to deployed policies, thresholds or thesis.

## Artifacts

| File | Content | sha256 |
|---|---|---|
| `../../scripts/revision_tensor_indicator_features.py` | feature extraction | `cb5ac30d50794358b8b0c556a1ab339a24e8f4d890ab2f3a2d8c146f857dbd6e` |
| `../../scripts/revision_tensor_indicator_eval.py` | evaluation | `bc33e2dfed679076a22d4278be2afab222f5c46a57058b96b8bad5ce0139ec10` |
| `features.csv` | 15,660 client/round rows, 36 arms | `36bcf84bcc54c53001b590cacaee8207899f97610482d86422b15f072f435302` |
| `evaluation.json`, `evaluation-stdout.txt` | all rules × 1/2/5% clean FPR | — |

## Protocol

- Delta = submitted local model minus previous global checkpoint (round 1 skipped).
  Round-relative indicators: `rel_norm`, `cos_median` (coordinate median),
  `knn_rel` (mean distance to 3 nearest peers), `head_rel_norm` and
  `head_cos_median` (classification head only), `peer_top1/2` (collusion,
  FoolsGold-style), `self_temporal` (cosine with own previous delta),
  `global_align` (cosine with previous global step).
- Adverse direction fixed **a priori** from the threat model, never fitted.
- Robust z relative to 7,830 benign rows of clean arms (controlled clean,
  `gated_clean`, `tpm_clean`); thresholds at 1/2/5% clean FPR.
- Rule selection on development seeds 342593/343593; reported on holdout seeds
  344593/345593. Two attacked arms: `gated_adaptive` (attack optimized against the
  deployed composite) and `tpm_adaptive` (unconstrained attack). Attack rounds 11–30,
  attackers client02/05/14, 120 attacker observations per arm and split.
- Families: legacy-like, geometry (5 incl. head), collusion, temporal, all; scores
  max / second max / mean of capped z; per-client CUSUM (k = clean median).

## Single-indicator AUC (attacker vs benign, attack rounds)

| Indicator | dev gated | dev tpm | hold gated | hold tpm |
|---|---:|---:|---:|---:|
| recorded legacy `s` | 0.760 | — | 0.673 | — |
| `head_cos_median` | 0.885 | 0.987 | 0.928 | 0.944 |
| `head_rel_norm` | 0.823 | 0.914 | 0.941 | 0.859 |
| `knn_rel` | 0.811 | 0.934 | 0.704 | 0.832 |
| `rel_norm` | 0.720 | 0.890 | 0.676 | 0.794 |
| `cos_median` | 0.668 | 0.891 | 0.609 | 0.778 |
| `global_align` | 0.672 | 0.622 | 0.550 | 0.589 |
| `self_temporal` | 0.425 | 0.463 | 0.451 | 0.379 |
| `peer_top1` | 0.377 | 0.539 | 0.528 | 0.594 |

## Holdout results at 2% clean FPR

| Rule | gated attackers | tpm attackers | benign Q (gated arm) | attacker share (no gate 20.0%) |
|---|---:|---:|---:|---:|
| Recorded legacy `s` (deployed) | 2/120 | n/a | 2.3% | 20.1% |
| CUSUM of legacy `s` | 6/120 | n/a | 3.5% | 19.6% |
| geometry: max | 86/120 | 91/120 | 0.6% | 5.8% |
| **CUSUM[geometry: max]** (selected on dev) | **90/120** | **111/120** | 1.3% | **5.1%** |
| CUSUM[all: second max] | 84/120 | 110/120 | 2.3% | 6.0% |

No rule broke the 10-contributor quorum at 2% FPR; every rule using geometry
quarantined all 290 controlled trusted attacked inputs. Legacy `s` does not exist
on TPM-only arms. First flagged round per holdout attacker for the selected rule:
rounds 14–18 on `gated_adaptive`, 12–13 on `tpm_adaptive` (attack starts at 11).

## Findings

1. **The missing signal is in the classification head.** Head-only geometry raises
   single-indicator AUC from 0.67–0.76 (legacy) to 0.93–0.94 on holdout. The deployed
   indicators are computed on the whole model, where the head is a small fraction
   of the parameters.
2. A non-compensatory max over geometry plus per-client CUSUM catches 90/120
   holdout gated attackers vs 2/120 for the deployed rule at the same clean FPR,
   reducing the attacker share in attack rounds from 20% to about 5%.
3. Collusion and temporal self-consistency indicators do **not** help with their
   a-priori direction: these adaptive attackers are less mutually similar and
   less self-consistent than benign clients. They are kept in the tables, not tuned.
4. CUSUM detects with a 1–7 round delay; first attack rounds still pass.

## Limits

Fixed trajectories: the adaptive attacker did not know about head indicators and
could constrain head deltas if it did. Clean calibration pools all seeds (clean
data only). Four seeds, one dataset (Data24), IID-like cohorts in these arms: the
earlier non-IID failures of the statistical gate are not tested here. No ASR is
measured. The selected rule is a development candidate; promotion needs an
independent live study with predeclared thresholds, a defender-aware adaptive
attack (including a head-constrained variant), non-IID assignments, and per-round
benign-mass budgets.
