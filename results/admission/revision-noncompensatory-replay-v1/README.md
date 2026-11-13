# Non-compensatory admission score replay (exploratory)

Completed 2026-11-10. Offline, fixed-trajectory replay of alternative statistical
admission scores on the retained decisions already checked by the
[gate mechanism audit](../../gates-probes/revision-gate-mechanism-audit-v1/README.md). No training,
no test inference, no change to deployed policies, thresholds or thesis.

Generator: `scripts/revision_noncompensatory_replay.py`
(sha256 `5e0b28a086c1a081b9f0f06eb1efe45f2de586d69d48bc54ba167a466e1bd1ac`).
Outputs: `replay-results.json` (all operating points) and `replay-stdout.txt`.

## Data and protocol

- 12,600 recorded decisions from 28 campaigns; the 600 controlled trust failures
  are vetoed by every integrated rule and excluded, leaving 12,000.
- Thresholds are calibrated **only** on the 6,300 benign decisions of clean
  campaigns (controlled `clean` and adaptive `gated_clean`), at matched benign
  quarantine rates of 1%, 1.97% (the current rule's rate) and 5%.
- Evaluated on 240 active adaptive-attacker submissions (4 seeds), 300 controlled
  trusted attacked inputs, benign decisions of attacked arms, per-round quorum
  (>=10 of 15) and exact example-weighted attacker share in attack rounds.
- Signed robust z values are recomputed from recorded raw values and same-round
  clean references; "re-standardized" scores rescale each indicator by the
  median/MAD of the pooled clean z distribution.

## Main results (adaptive attackers quarantined out of 240)

| Score | 1% clean FPR | 1.97% | 5% |
|---|---:|---:|---:|
| Current mean `s` | 5 | 11 | 62 |
| Max adverse, re-standardized | 16 | 30 | 65 |
| 2nd-largest adverse z ("2 of 5"), original z | 39 | 54 | 86 |
| Per-client CUSUM of re-standardized max | 15 | 36 | 67 |
| Two-sided / Mahalanobis variants | 0–9 | 4–13 | 16–47 |

Attacker share in attack rounds falls from 19.7% (current) to 16.3% at 1.97% FPR
and 14.1% at 5% for the best rule. All rules quarantine the non-stealthy
controlled attacks (~300/300; CUSUM on `s` 210–240).

## Findings

1. Non-compensatory voting helps: about 5x more attackers at the current benign rate.
2. The ceiling is the signal: best single-indicator AUC 0.823
   (`coordinate_median_distance`); all scores 0.79–0.85 (attacker vs benign on the
   same attacked trajectories).
3. Reference miscalibration: 64% of clean benign `cosine_to_median` and 24% of
   `coordinate_median_distance` components are saturated at risk 1; the
   15-sample same-round MAD underestimates live benign spread.
4. Two-sided and covariance-based distances perform worse.
5. Ties: the "re-standardized mean" row at 1.97% has a degenerate threshold
   (0 clean FPR) and should not be interpreted.

## Limits

Fixed trajectories; the adaptive attack was optimized against the deployed
composite and would adapt to any new rule. Clean calibration uses the same seeds
(in-sample clean data). The 240 attacker observations are correlated within four
seeds. No ASR is measured. Any candidate derived here is a new development
candidate requiring independent live validation with predeclared thresholds.
