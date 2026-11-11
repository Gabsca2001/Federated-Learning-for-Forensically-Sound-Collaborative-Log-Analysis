# Fixing the probe's honest flags: offline development (persistence, per-key normalisation)

2026-11-11. **Development only.** No training and no test split. Replay of recorded local
models: 12 verified clean TPM-only calibration histories, plus the 172 archived cases
(guard + evaluation, every arm) of `revision-trigger-probe-live` and
`revision-trigger-probe-evasion-live`. These partitions are now development data, so any
rule chosen here must be confirmed on fresh partitions.
Scripts: `scripts/revision_probe_persistence_dev.py` (→ `../revision-probe-persistence-dev/`),
`scripts/revision_probe_keynorm_dev.py`, `scripts/revision_probe_keynorm_split.py`.
Probe vectors: `vectors.json` (18 MB, not committed; regenerable with `extract`).
Consistency check: the deployed rule replayed from the recomputed vectors reproduces the
recorded decisions exactly (65 honest flags, 18/172 cases with ≥2 consecutive exclusions).

## Diagnosis

Under the deployed rule (clean max of the raw peer-relative score), **53 of 65 honest flags
fall on feature 12** and 7 on feature 1. Neither is a trigger feature. Feature 12 is a
*natural* shortcut: pushing it to an extreme already moves attack rows towards benign, and
how strongly varies between honest clients, especially in non-IID. A single global threshold
cannot separate this natural variability from a backdoor.

## Rule 1: persistence (same feature in k of the last w rounds)

| Rule (clean-max threshold) | Honest flags | Longest honest run | DBA non-IID detected | Evasive non-IID detected |
|---|---:|---:|---|---|
| deployed | 65 | 5 | 55–77% | 29% |
| 2/2 | 24 | 4 | 40–51% | 19% |
| 3/3 | 7 | 3 | 30–37% | 14% |

Rejected. Honest anomalous clients persist on the *same* feature, and detection collapses.

## Rule 2: per-key normalisation

For each key (feature, value): excess = shortcut − round peer median. Each key is divided by
its own clean scale s_k = max(clean maximum of that key's excess in the cohort, 0.1), and the
client is quarantined when max_k excess_k / s_k > m. The scale comes from the 12 clean
calibration histories only.

Honest flags in the 68 **clean** cases (15,300 client-rounds), and attacker client-rounds
detected in rounds 1–10:

| Rule | Clean honest flags | Clean longest run | Clean cases failing (≥2 consecutive) | DBA IID / non-IID | Evasive IID / non-IID | Adaptive IID / non-IID |
|---|---:|---:|---:|---|---|---|
| deployed (raw clean max) | 16 | 2 | 4/68 | 100% / 55–77% | 91% / 29% | 2% / 1% |
| per-key m=1 | 336 | 15 | 34/68 | 100% / 100% | 100% / 95% | 16% / 3% |
| per-key m=1.5 | 23 | 2 | 1/68 | 100% / 100% | 100% / 93% | 11% / 3% |
| **per-key m=2** | **0** | **0** | **0/68** | **100% / 100%** | **100% / 93%** | 8% / 3% |

The DBA and evasive figures above are measured on every attack in both studies (distributed,
complete-trigger and pair DBA; evasive).

### Honest clients in attacked runs (m=2)

Honest clients are flagged in attacked runs too: 377 of 18,720 client-rounds. Most of these
are in TPM-only arms under the adaptive attack (227/2,880). There the global model is already
poisoned, so honest clients inherit the backdoor. In the probe+bounded arms of the previous
live study, where the attackers are removed, they are rare (DBA 4/2,880). They remain 26/1,440
(1.8%) under the adaptive attack, which the probe does not remove. Whether these flags occur
in consecutive rounds still has to be checked live.

## Reading

* Per-key normalisation addresses the actual cause: it gives feature 12 a higher bar and keeps
  the stable features sensitive. With m=2 it removes every honest flag in the clean cases
  while detecting DBA completely in non-IID as well (up from 55–77%) and the probe-aware
  evasive attacker in 93–100% of attack rounds. The evasive models still show single-feature
  shortcuts at 12 standard units, because the attacker hid only the trained value (6). With
  this rule the pair probe becomes unnecessary for this attacker.
* **Selection caveat:** m=2 is the smallest value in a grid {1, 1.25, 1.5, 2} that gives zero
  clean flags here. It was picked with these data visible, and the floor 0.1 was fixed without
  tuning. This is development evidence, not confirmation.
* **Open:** confirm live on fresh partitions with the rule frozen. The confirmation needs a
  guard (clean), an evaluation (DBA, evasive, adaptive) and consecutive-exclusion checks in
  attacked runs. A stronger attacker that negatively augments *all* probe values (3/6/12) is
  not covered.
