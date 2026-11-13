# Gate / defence research: handoff (2026-11-11)

Branch `revision/head-gate-studies`. This page summarises the gate research: what holds, what failed and what is still open.

## What is established (all on Data24, software trust assumption)

| Finding | Strength | Evidence |
|---|---|---|
| Sequential ≡ Gated Composite (same exclusion set); averaged 5-indicator score is weak/compensatory | proven + verified on 12,600 decisions | `results/gates-probes/revision-gate-mechanism-audit-v1`, `results/admission/revision-noncompensatory-replay-v1` |
| Composite is fragile in non-IID (excludes 10–26% honest clients, quorum loss) | observed in every study | all study READMEs below |
| **Per-tensor clipping contains adaptive (scaled) attacks** (final ASR ≈ 0, no benign cost) | **confirmed** on fresh assignments (K1 29/1/2) | `results/gates-probes/revision-head-gate-v2-confirm/README.md` |
| **Behavioural trigger probe removes DBA**, IID and non-IID, zero honest exclusions | **confirmed live** (P1 16/1/7, P2 14/0/2, P3 18/0/0) | `results/gates-probes/revision-trigger-probe-live/README.md` |
| probe + clipping are complementary (probe: DBA; clipping: adaptive) | live | same |
| Geometric head gates (v1 head_cusum, v2 step-normalized, v3 round-relative) have unstable false positives (persistent per honest client) | documented; stop rule applied | `results/gates-probes/revision-head-cusum-gate-v1`, `-head-gate-v2-exploratory`, `-v2-confirm`, `-v3-dev` |
| Bug: `_dirichlet_assignments` seed+attempt → consecutive seeds can share partitions | erratum; new studies check distinctness | `results/gates-probes/revision-head-cusum-gate-v1/README.md` |
| **Probe vs probe-aware AND-trigger attacker (live)**: both probe arms fail the clean guard (honest client excluded 2 / 5 consecutive rounds); pair-probe clean-max thresholds ≈1 (inert). Pair attacks: clipping gives no protection in non-IID (peaks 48–100%) | predeclared live, hypotheses undefined (arms not qualified) | `results/gates-probes/revision-trigger-probe-evasion-live/README.md` |
| **Per-key normalised probe (probek, x2 clean max per feature/value) vs pair DBA / evasive / adaptive (live, confirmatory)**: all arms pass the guard; K1-K3 hold (adds to clipping, beats reference); non-IID peaks 55.6->10.6 (DBA), 50.7->15.7 (evasive); adaptive attacker not stopped (non-IID 73.5% in all bounded arms) and causes honest exclusions up to 5 consecutive rounds in 2/8 runs; evasive controls weak (3/8) | predeclared live, confirmed with stated limits | `results/gates-probes/revision-probe-keynorm-confirm/README.md` |
| **Global-model probe with rollback (probekg: drift vs initial model > 1.5x clean max per key -> keep previous global) on top of probek + clipping (live, confirmatory)**: all arms pass the guard; G1-G4 hold (adaptive peak 52-84% -> 21-28%, final 0; 0 honest exclusions in attacked runs; no clean rollback). Cost: learning stalls during adaptive attack (F1 r10 up to -15 pt, recovered by r15) | predeclared live, confirmed with stated limits | `results/gates-probes/revision-global-probe-confirm/README.md` |

Probe development (detection, generality to 4 unseen triggers, threshold severity, AND-trigger
evasion offline): `results/gates-probes/revision-trigger-probe-dev/README.md`, `results/gates-probes/revision-trigger-probe-thresholds/`.

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

Done: probe-aware, per-key and global-rollback live studies. Since then the probe and the rollback have become opt-in nodes of the signed derivation graph
(commit 26b6a26, `results/gates-probes/revision-live-probe-rollback-v1`); the live rollback never
triggered and is covered by unit tests. Open: (1) a live case in which the rollback fires; (2) drift-spreading / slow-drift adaptive attackers vs the global probe;
(3) a second dataset; (4) discriminative pair-probe score. Optional: swtpm.

## Environment notes (important)

* Windows Git Bash strips `$VAR` in inline `wsl.exe ... bash -lc '...'` commands: put logic in a
  script file and run `MSYS_NO_PATHCONV=1 wsl.exe -d ubuntu -- bash /mnt/c/.../script.sh`.
* Run at most 2 training workers; no other heavy WSL job in parallel.
* Disk: free space on C: is limited. Old artifacts are archived on the external SSD
  (`docs/records/ARTIFACT_OFFLOAD.md`, manifest `results/records/artifact-offload/manifest.jsonl`). After each
  study: archive cases, `wsl -u root fstrim -v /`; compaction needs every program that uses WSL (Docker, editors, terminals)
  closed and an admin PowerShell on C:\ running `C:\Users\scama\compact-wsl.ps1`.
* Never present exploratory results as confirmed; disclose guard failures and deviations.
