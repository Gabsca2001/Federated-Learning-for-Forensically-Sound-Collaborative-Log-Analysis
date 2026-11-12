# Global-model probe with rollback: verified results

Protocol: [PROTOCOL.md](PROTOCOL.md). Freeze `protocol-before-guard.json` sha256
`53733768f7b13432831308d769ece4ecdd4c6ff6de73fc225a9b15239dd4adab`, committed in 7aa5dc6 before training.
The refitted global scales matched development exactly. Floor 0.1 and ×1.5 were not changed.

**Deviation (before training):** the first smoke run found a controller bug, a `KeyError` in the
gate-state wiring. No study training had started. The bug was fixed, and the lab and the first freeze
(sha d3598842…) were deleted and re-prepared on the same seeds. Only the second freeze, the one
committed above, was used.

## Pipeline status

| Step | Outcome |
|---|---|
| Guard (16 clean cases) | Independently verified. **All 4 arms qualify**, including `probekg+bounded`. |
| Evaluation (128 cases) | 127 complete. One quorum failure: `non-iid-s2027821001-probek+bounded-adaptive` at round 11, because too many honest clients were excluded. Every round was independently verified, including recomputation of each global-probe score and rollback. |
| Test | Opened only after verification. Outputs from `scripts/report_arm_study.py`. |

## Hypotheses

| Id | Comparison | lower / higher / equal / undefined | Holds |
|---|---|---|---|
| G1 | probekg vs probek, adaptive | 7 / 0 / 0 / 1 (the quorum failure) | **yes** |
| G2 | probekg vs tpm_only+bounded, all attacks | 24 / 0 / 0 / 0 | **yes** |
| G3 | probekg vs tpm_only+fedavg, effective controls | 20 / 0 / 0 / 0 | **yes** |
| G4 | attacked guard: honest quarantine ≤5% and no consecutive honest exclusion, all 24 attacked probekg runs | 0.00% honest quarantine, longest run 0 | **yes** |

## Mean peak / final attack success (4 seeds, %)

| Cohort | Variant | fedavg | bounded | probek+bounded | probekg+bounded |
|---|---|---|---|---|---|
| IID | pair-dba | 23.4 / 0 | 13.6 / 0 | 0 / 0 | 0 / 0 |
| IID | evasive | 3.5 / 0 | 1.5 / 0 | 0 / 0 | 0 / 0 |
| IID | adaptive | 100 / 100 | 69.2 / 0 | 52.3 / 0 | **20.9 / 0** |
| non-IID | pair-dba | 61.1 / 22.1 | 64.0 / 21.6 | 0 / 0 | 0 / 0 |
| non-IID | evasive | 57.8 / 28.4 | 59.9 / 28.7 | 0.1 / 0.1 | 0.1 / 0.1 |
| non-IID | adaptive | 100 / 86.3 | 88.3 / 49.5 | 84.4 / 49.6 (3 runs) | **27.8 / 0** |

## Secondary endpoints (descriptive)

**Rollback rounds** in probekg+bounded:

| Variant | IID | non-IID |
|---|---|---|
| clean | 0/60 | 0/60 |
| pair-dba | 0/60 | 0/60 |
| evasive | 0/60 | 0/60 |
| adaptive | 22/60 | 32/60 |

**Honest exclusions under the adaptive attack, without the global probe (probek+bounded):**
* honest quarantine 2.6% (IID) and 3.8% (non-IID)
* consecutive honest exclusions in 5 of 8 runs, up to 9 rounds
* one quorum failure

With probekg there are none in any attacked run, so the rollback removes the failure mode
seen in the key-norm study.

**Attacker quarantine (rounds 1–10)** is the same for probek and probekg:
* pair-dba: 240/240
* evasive: 238/240
* adaptive: almost none (0–3/120)

The adaptive attacker is contained by rollback, not by exclusion.

**Cost:** there is no false rollback on clean data. Under the adaptive attack, repeated rollbacks
stall learning: validation F1 at round 10 drops in some runs, by up to 15 points (non-IID
s2027822001: 0.785 vs clean 0.940). F1 recovers by round 15 in every run (within 1 point of clean).

**Effective reference controls:**
* pair-dba 8/8
* adaptive 8/8
* evasive 4/8, which reaches the threshold for a non-weak evasive part

## Reading

* On fresh partitions, the full defence (per-key client probe + clipping + global probe with
  rollback) passes the clean guard and the predeclared attacked guard. It reduces harm against every
  attack compared with clipping alone and with the reference.
* Against the adaptive attacker, peak success drops from 52–84% to 21–28%, and final success is 0
  in every run.
* Limits:
  * Peak success is not zero: the attacker gets through before the drift exceeds the threshold.
  * Containment costs availability: training stalls during the attack.
  * One dataset (Data24), software trust assumption.
  * Floor and multiplier come from development. They were confirmed here, not tuned.
* The adaptive attacker in this study optimises the interpolation strength against the complete
  defence, rollback included. An attacker that spreads drift across many keys, or that keeps it just
  below 1.5× for many rounds, was not tested.

Cases are archived one tar.gz per case after verification (`artifacts/revision-global-probe-confirm/ARCHIVE-RECORD.json`).
