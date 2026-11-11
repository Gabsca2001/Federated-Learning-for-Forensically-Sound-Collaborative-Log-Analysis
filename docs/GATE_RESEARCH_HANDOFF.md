# Gate / defence research: handoff (2026-11-11)

Branch `revision/head-gate-studies` (not pushed). Read this first in a new session.

## What is established (all on Data24, software trust assumption)

| Finding | Strength | Evidence |
|---|---|---|
| Sequential ≡ Gated Composite (same exclusion set); averaged 5-indicator score is weak/compensatory | proven + verified on 12,600 decisions | `results/revision-gate-mechanism-audit-v1`, `results/revision-noncompensatory-replay-v1` |
| Composite is fragile in non-IID (excludes 10–26% honest clients, quorum loss) | observed in every study | all study READMEs below |
| **Per-tensor clipping contains adaptive (scaled) attacks** (final ASR ≈ 0, no benign cost) | **confirmed** on fresh assignments (K1 29/1/2) | `results/revision-head-gate-v2-confirm/README.md` |
| **Behavioural trigger probe removes DBA**, IID and non-IID, zero honest exclusions | **confirmed live** (P1 16/1/7, P2 14/0/2, P3 18/0/0) | `results/revision-trigger-probe-live/README.md` |
| probe + clipping are complementary (probe: DBA; clipping: adaptive) | live | same |
| Geometric head gates (v1 head_cusum, v2 step-normalized, v3 round-relative) have unstable false positives (persistent per honest client) | documented; stop rule applied | `results/revision-head-cusum-gate-v1`, `-head-gate-v2-exploratory`, `-v2-confirm`, `-v3-dev` |
| Bug: `_dirichlet_assignments` seed+attempt → consecutive seeds can share partitions | erratum; new studies check distinctness | `results/revision-head-cusum-gate-v1/README.md` |
| **Probe vs probe-aware AND-trigger attacker (live)**: both probe arms fail the clean guard (honest client excluded 2 / 5 consecutive rounds); pair-probe clean-max thresholds ≈1 (inert). Pair attacks: clipping gives no protection in non-IID (peaks 48–100%) | predeclared live, hypotheses undefined (arms not qualified) | `results/revision-trigger-probe-evasion-live/README.md` |
| **Per-key normalised probe (probek, x2 clean max per feature/value) vs pair DBA / evasive / adaptive (live, confirmatory)**: all arms pass the guard; K1-K3 hold (adds to clipping, beats reference); non-IID peaks 55.6->10.6 (DBA), 50.7->15.7 (evasive); adaptive attacker not stopped (non-IID 73.5% in all bounded arms) and causes honest exclusions up to 5 consecutive rounds in 2/8 runs; evasive controls weak (3/8) | predeclared live, confirmed with stated limits | `results/revision-probe-keynorm-confirm/README.md` |

Probe development (detection, generality to 4 unseen triggers, threshold severity, AND-trigger
evasion offline): `results/revision-trigger-probe-dev/README.md`, `results/revision-trigger-probe-thresholds/`.

## Code map

* Engine adapters: `scripts/revision_gate_trajectories.py` (engine), `revision_head_v2_study.py`
  (numerical operators incl. `bounded`), `factorial_aggregators.py`.
* Probe: `scripts/trigger_probe_gate.py` (gate), `revision_probe_study.py` (controller),
  `revision_probe_audit.py` (verifier); tests `tests/test_trigger_probe_gate.py`.
* Generic: `revision_head_cusum_test.py --lab L [--phase P]` (test phase, refuses unless closed+verified),
  `report_arm_study.py --lab L --out O [--phase P] [--hypothesis a,b,v1|v2[,effective]]`.
* Pattern of every study: prepare (freeze protocol, partitions distinct) → guard (clean) →
  verify → guard-decide → evaluation → verify → test (precommit) → report → archive cases (tar.gz).

## Next planned experiment

Done: probe-aware live study and per-key probe confirmation (`results/revision-probe-keynorm-confirm/`).
Open: (1) the adaptive interpolation attacker evades probek (4/240 quarantined) and drives honest
persistent exclusions; a guard under attacked conditions is needed; (2) a stronger evasive live
attacker (3/8 effective controls); (3) discriminative pair-probe score. Optional: swtpm.

## Environment notes (important)

* Windows Git Bash strips `$VAR` in inline `wsl.exe ... bash -lc '...'` commands: put logic in a
  script file and run `MSYS_NO_PATHCONV=1 wsl.exe -d ubuntu -- bash /mnt/c/.../script.sh`.
* Run at most 2 training workers; no other heavy WSL job in parallel.
* Disk: C: had 56 GB free after compaction. Old artifacts are archived on the external SSD
  (`docs/ARTIFACT_OFFLOAD.md`, manifest `results/artifact-offload/manifest.jsonl`). After each
  study: archive cases, `wsl -u root fstrim -v /`; compaction needs the Claude app, Docker and
  VS Code closed and an admin PowerShell on C:\ running `C:\Users\scama\compact-wsl.ps1`.
* Never present exploratory results as confirmed; disclose guard failures and deviations.
