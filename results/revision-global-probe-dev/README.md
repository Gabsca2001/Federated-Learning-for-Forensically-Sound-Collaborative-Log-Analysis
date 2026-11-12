# Global-model probe: offline development (not confirmatory)

Script: `scripts/revision_global_probe_dev.py`. Data:
* 12 verified clean TPM-only calibration histories, used to fit scales only.
* 208 archived cases of `revision-probe-keynorm-confirm` and `revision-trigger-probe-evasion-live`.

Uses validation rows only. No training, no test split.

Rule: drift_k(r) = probe shortcut_k of the global model at round r − that of the initial model.
Alarm when max_k drift_k / max(clean max drift_k, floor) > multiplier.

## Result (detection only; floor and multiplier chosen with these data visible)

| Rule | Clean runs alarmed (60) | Adaptive runs alarmed, IID / non-IID (bounded arms) |
|---|---|---|
| floor 0.1, ×1.0 | 17 | 12/12 / 9/12 |
| **floor 0.1, ×1.5** | **0** | **12/12** (first alarm round 4–6) / **9/12** |
| floor 0.1, ×2.0 | 0 | 12/12 (round 8–9) / 6/12 |
| floor 0.1, ×3.0 | 0 | 1/12 / 3/12 |

* With ×1.5, alarms fall mainly on attacked features: 11 (pair {11,22}), 8 ({8,15}) and 3 ({3,18}).
* The peer-relative probes already stop pair-dba and evasive attacks, and the global probe stays
  silent on those runs (0/32).
* Missed: non-IID seed 2027722001 under the adaptive attack, which caused 49% harm.
* Margin is thin: ×1.0 already gives 17 clean alarms.

Detection is not mitigation. Whether a rollback to the previous global model on alarm
actually limits the attack, and avoids the honest exclusions, can only be measured live.
