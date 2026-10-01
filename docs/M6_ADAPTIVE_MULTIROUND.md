# Paired adaptive multiround protocol — 2026-09-28

> **Completion update — 2026-09-30:** all four adaptive extension pairs are verified.
> The [five-seed report](../results/m6-adaptive-multiseed-v1/README.md) includes paired endpoints,
> trajectories and admission counts. Selected test ASR is 0/669 in both arms for every seed.
> The mean adaptive-minus-clean macro-F1 difference is +0.4038 pp across all five
> seeds (+0.1367 pp for the four new seeds). These are descriptive outcomes, not
> proof of universal robustness or beneficial poisoning. Earlier running/pending
> statements below are historical. The original locked protocol is unchanged.


> **Current status (2026-09-29):** the active-policy five-seed comparison, fixed-signal
> sensitivity, live +10% sensitivity, adaptive frozen pilot, signed smoke and paired
> v4 seed341593 are completed. The four additional adaptive seed pairs are running;
> their results are not yet available. See [current result index](../results/README.md)
> and [publication checklist](PUBLICATION_READINESS.md). Dated preparation, stopped,
> pending and running notes below are historical execution records, superseded by
> the later completion/recovery entries. Original locked protocols remain unchanged.

## Scope fixed before execution

`configs/m6-adaptive-paired-s341593-v1.json` defines an exploratory single-seed
paired experiment. Both arms train 15 clients for 30 rounds, seed 341593, IID
partition, CPU, unchanged original gated-composite policy. The adaptive arm uses
clients 02, 05 and 14 in rounds 11–30; rounds 1–10 are clean. The separate clean
arm has no intervention. Initial ten global checkpoints must match byte for byte.

The same local-training runtime image is required by immutable image ID. Existing
TPM identities are reused in distinct fresh campaigns, with fresh attestations each
round; prior campaigns and logs remain intact. Additional adaptive scripts are bound
by signed coordinator precommits, not retrospectively added to the M4 PCR baseline.
Code, plan, policy, partition and validation digests and host package versions are
recorded in an execution lock before training. A changed locked input stops execution.

## Attack and selection

The algorithm is unchanged from the verified smoke: four radius restarts, 16 gradient
proposals per radius, clean and fixed controls, 66 total queries per attacked round
(1,320 across 20 rounds). It observes all original proposals and the exact validation
oracle. Controls cannot win selection. Feasible selection maximizes reconnaissance-
to-benign ASR, then minimizes target cross-entropy, then prefers the earliest query.
If no adaptive proposal is feasible, all original contributions are submitted and
the unsuccessful search is preserved; budgets and thresholds are not increased.

Original proposals are preserved, selected updates receive new TPM signatures, and
subsequent rounds train from the actual admitted checkpoint. Every round is verified.
Attacked rounds additionally recompute the complete search and require exact agreement
between the predicted aggregate and the actual checkpoint. Signed experimental
provenance is checked independently before advancing.

## Outcomes and evaluation boundary

Primary descriptive endpoints compare the two validation-selected checkpoints on
pooled test reconnaissance-to-benign ASR and macro-F1. The existing M5 selection rule
(maximum validation macro-F1, earliest tie) remains unchanged; selecting a pre-attack
checkpoint is a legitimate protective outcome and must be reported as such.
Secondary summaries cover validation trajectories, per-round targeted damage,
attacker admission and interventions affecting honest clients. No extra final-round
test evaluation is introduced under a selected-checkpoint-only protocol.

Neither arm is finalized on test until both complete and verify all 30 rounds.
The optimizer never receives test data. The dataset has been used in earlier studies;
this is an exploratory experiment, not a new confirmatory holdout. One paired seed
cannot establish statistical superiority or universal robustness. The round-1 smoke
success and frozen round-11 negative result remain separately reported.

## Execution and evidence

Run `python scripts/run_m6_adaptive_paired.py` from the repository virtual environment.
The runner refuses an existing destination; it does not overwrite or automatically
restart a partial campaign. Evidence is under
`artifacts/m6-adaptive-paired-s341593-v1/{clean,adaptive}`; the immutable execution
lock is at the pair root. The local log is `m6-adaptive-paired-s341593-v1.log`.
A per-round verifier is available as `scripts/verify_m6_adaptive_paired.py`.
Completion is explicitly marked `ADAPTIVE PAIRED CAMPAIGN VERIFIED` only after
both final campaign verifications. A traceback means investigate before continuing.

Nine focused tests passed, including signed-authorization tampering and the no-feasible-
candidate fallback. Undefined-name checks passed. The trial has not yet produced
multiround results. After completion, publish paired trajectories, confusion-derived
ASR denominators, selected rounds and honest-client interventions, with source hashes.

## Fresh-node correction before training — v2

The v1 paired attempt was stopped at the first attestation, before any training:
all nodes returned failed_measurement. The simulator entrypoint uses startup-clear;
restarting the smoke's stopped TPMs no longer matches the prior measured PCR state.
Quote verification correctly rejected the mismatch. No trust checks are bypassed.
The failed v1 experiment and trust results remain preserved.

The operative plan is now `configs/m6-adaptive-paired-s341593-v2.json` and runner
`scripts/run_m6_adaptive_paired_v2.py`. It provisions fresh nodes in its own Docker
namespace and holds them active across both arms. Scientific settings, attack schedule,
query budget and endpoints are unchanged. New evidence is under
`artifacts/m6-adaptive-paired-s341593-v2`; local log:
`m6-adaptive-paired-s341593-v2.log`. A TPM restart during execution requires stopping
and investigating, not silently reusing prior attestation state.

## Local-image recovery — v3

V2 provisioning stopped before creating TPMs: the WSL/Windows credential helper
failed during Docker image metadata resolution. The actual message was
`error getting credentials` with `UtilAcceptVsock ... accept4 failed 110`.
No training occurred. All failed workspaces and logs remain preserved.

The operative runner is `scripts/run_m6_adaptive_paired_v3.py`, plan
`configs/m6-adaptive-paired-s341593-v3.json`, log
`m6-adaptive-paired-s341593-v3.log`. It uses fresh nodes and the official
`run_m4_swtpm.py provision --skip-build` path. All 31 measured source files
inside the previously verified M4 image matched the current repository by SHA-256.
That immutable image is recorded in the v3 plan and locally tagged for the new
services. No global Docker credential settings or verification rules are changed.
The scientific protocol remains the same; this change concerns provisioning only.
V3 recovery: all 15 fresh TPMs started, but client01 provisioning could not create
its trust network because Docker address pools were fully subnetted. No client
provisioning or training had completed. Only the old smoke-v1 trust network was
removed, after confirming its container set was empty; all volumes remain.
`scripts/recover_m6_adaptive_paired_v3.py` resumes provisioning without restarting
TPMs, requires the original execution lock to match and no arm to have started,
and records its code digest in a recovery receipt bound by campaign precommits.
Recovery log: `m6-adaptive-paired-s341593-v3-recovery.log`.

## V3 stopped by strict pre-attack reproducibility check

The clean arm completed 30 rounds. The adaptive arm stopped at round 1 before
any adaptive treatment: its aggregate was not byte-identical to the clean round.
The bases and configuration match exactly; 14 client updates match exactly.
Client01 differs in 288/13862 values, maximum absolute difference
1.4901161193847656e-08. The aggregate maximum difference is
2.9802322387695312e-08. All admission statuses and all 3223 validation predictions
are unchanged, although gate scores differ in trailing digits. Neither arm was
finalized and no test evaluation was run.

This is consistent with small numerical reproducibility variation, not demonstrated
attack damage. The exact low-level cause has not been proven. Two independent
unsigned client01 diagnostic replays with one intra-op/inter-op thread,
OMP/MKL/OpenBLAS threads fixed to 1 and MKL_CBWR=COMPATIBLE produced the identical
hash d57b0cc25aaa329c632e081d9ff810690aa2eebd782391b5f94a24b823759f33.
This supports testing an explicit numerical runtime configuration for a new paired
run, but two repetitions alone do not guarantee determinism across all clients.

The original lock, comparison criterion, 30 clean rounds and failed adaptive round
remain unchanged. The current campaign is stopped; no tolerance was relaxed after
observing this discrepancy. See `results/m6-adaptive-paired-v3-reproducibility-incident/diagnosis.json`.


## V4 numerical runtime and paired execution — prepared before restart

Thirty-six independent container probes passed exact model-hash equality: two
repetitions for every client at round 1 and clients 01, 02, 15 at round 10.
The results and code digests are in `results/m6-numeric-runtime-preflight-v1`.
This is finite supporting evidence, not a guarantee for all future rounds.

V4 uses `scripts/m6_numeric_runtime.py` to set one Torch intra/inter-op thread,
one OMP/MKL/OpenBLAS/NumExpr thread and MKL_CBWR=COMPATIBLE before numerical
imports. Training, signing, coordinator numerical commands, search and verification
use this runtime. Two clients run concurrently. Both arms are rebuilt in a fresh
pair workspace; no previous checkpoint is overwritten or reclassified.

Arms now progress round by round (clean then adaptive), so the unchanged exact
pre-attack equality check runs immediately at each of rounds 1–10. Attack timing,
query budget, policy, seed, dataset and selected-checkpoint-only test rule remain
unchanged. The currently running v3 TPMs are reused with fresh attestations and
startup timestamps bound in the execution lock; a restart stops the run.

Operative runner: `scripts/run_m6_adaptive_paired_v4.py`; plan:
`configs/m6-adaptive-paired-s341593-v4.json`; log:
`m6-adaptive-paired-s341593-v4.log`. Completion still requires both 30-round arms
and final verifications. No numerical tolerance replaces the original equality gate.

## V4 interruption before adaptive round 10

At inspection on 2026-09-28 15:25 local time, the main log had not changed since
14:02:11. The orchestrator process was absent, and client10's quote container
remained in created state with PID 0 and no start timestamp. No OOM entry was
found in the queried kernel journal; the disappearance cause is not established.
Ten clean and nine adaptive rounds are retained. No adaptive round-10 signed
context exists. The never-started container state was preserved in the pair's
`client10-unstarted-container.json` before removing that temporary container only.

`scripts/resume_m6_adaptive_paired_v4.py` preserves the original lock and precommits,
requires matching code/runtime/TPM boot timestamps, signs separate resume receipts,
and reverifies completed rounds before refreshing attestations and continuing.
Its syntax was checked in the existing Python container. The detached launcher
`scripts/start_m6_resume_detached.py` refuses duplicate campaign processes and
writes a fresh log `m6-adaptive-paired-s341593-v4-resume.log` plus a process receipt.
Windows-to-WSL launch attempts are encountering 0x8007274c timeouts; restart is not
confirmed until the new process receipt/log is present. No TPM restart was performed.
## Completed paired adaptive v4 — 2026-09-29 analysis

Both 30-round trajectories completed and verified on 2026-09-28 at 18:30 local
(log marker ADAPTIVE PAIRED CAMPAIGN VERIFIED). This supersedes the earlier
running/interrupted status notes, retained above as execution history. The recovery
reverified existing rounds and preserved the original lock. TPMs were stopped by
the completed runner after final verification, not restarted during recovery.

Selected checkpoints: clean round 20, adaptive round 25. Pooled test macro-F1 is
0.9242495921 and 0.9389700250 respectively (adaptive minus clean +1.4720 percentage
points). Targeted reconnaissance-to-benign test ASR is 0/669 for both. None of the
20 adaptive search rounds met the prespecified success criterion (1,320 queries).
All 60 malicious client-round contributions participated: 32 accepted and 28
accepted downweighted. Thus contribution admission is not equivalent to achieving
the attack objective. Honest interventions in rounds 11–30 were 73 downweighted
and 8 quarantined out of 300 clean decisions, versus 47 and 3 out of 240 adaptive
honest decisions; denominators differ and these are descriptive counts.

The first ten paired checkpoints match byte for byte. Selection in the adaptive
arm occurred after attack onset; the zero-ASR finding is not explained by choosing
a pre-attack checkpoint. One seed does not establish statistical superiority,
universal robustness, or a beneficial effect of poisoning. No additional test
inference or post-test tuning was performed for the report.

Report: `results/m6-adaptive-paired-v4/README.md`, source-bound JSON results and four
PNG/PDF figures. Generator: `scripts/report_m6_adaptive_paired_v4.py`. Checks cover
locked files, checkpoint/evaluation/decision hashes, exact pre-attack pairing,
selected query metrics and validation-based checkpoint selection. Existing M8
preservation packages do not yet cover this new experiment. Next: prespecify the
multiseed extension before running it, then extend investigative/preservation
artifacts and thesis discussion. No new experiments were launched by this report.
## Adaptive four-seed extension launched — 2026-09-29

The protocol is fixed in docs/M6_ADAPTIVE_MULTISEED_V1.md and
configs/m6-adaptive-multiseed-v1.lock.json before training. Four new seeds
342593–345593 repeat the unchanged v4 attack and gated-composite defense in paired
clean/adaptive trajectories (240 new rounds, 5,280 search queries). The previously
observed seed 341593 remains explicitly exploratory; no new attack objective or
post-test parameter tuning is included. See the protocol for endpoints and limits.

Runner scripts/run_m6_adaptive_paired_seed.py adds explicit seed-specific federation
and partition checks without changing locked v4 sources. The supervisor
scripts/run_m6_adaptive_multiseed_v1.py uses fresh TPM workspaces and existing M4/M5
commands, verifies immutable inputs and stops on any failed step. Eleven focused
tests and undefined-name checks passed. Live log: m6-adaptive-multiseed-v1.log.
The detached launch receipt is artifacts/m6-adaptive-multiseed-v1-process.json.

All 31 measured M4 image files matched the host. The first preflight probe used
python instead of python3, which is what Dockerfile.m4 provides; it failed before
any network removal or training. After correcting that probe, four historical clean
policy network bridges were inspected and released only after confirming they had
no attached containers or active project containers. Inspection snapshots are under
results/m6-adaptive-multiseed-preflight-v1. All volumes and evidence remain intact.
No new results are claimed until each full pair and final evaluation verify.

## Invocation recovery — 2026-09-29
The first multiseed launch stopped after successful M4 provisioning/enrollment/mTLS, before any pair workspace or training. The seed runner re-exec omitted its plan argument, causing IndexError. Locked files remain unchanged. scripts/recover_m6_adaptive_multiseed_invocation_v1.py invokes the existing numerical wrapper explicitly with the plan argument, preserves the original lock, writes a separate recovery receipt and requires the first seed TPMs still running. Subsequent seeds still provision fresh nodes. All fifteen first-seed TPMs were confirmed healthy; syntax was checked in the existing container. New log: m6-adaptive-multiseed-v1-recovery.log. Windows-to-WSL launches currently time out; successful restart requires the recovery process receipt and advancing log.


### Second invocation correction — 2026-09-29
The first recovery preserved the seed argument but passed a relative script path. Path(__file__).relative_to(ROOT) then failed before writing the pair lock or starting training. The pair directory was confirmed empty. Separate recovery v2 passes the absolute runner path through the unchanged numerical wrapper. Its exclusive process guard and original input lock checks remain; it removes only the empty pair directory with nonrecursive rmdir, refusing any contents. A subprocess probe verified absolute __file__, preserved seed argument and numerical runtime before launch. Original scripts, locks, receipts and logs remain unchanged. Recovery v2 launched as PID 2305906; active log m6-adaptive-multiseed-v1-recovery2.log. See scripts/recover_m6_adaptive_multiseed_invocation_v2.py and artifacts/m6-adaptive-multiseed-v1-invocation-recovery2.json.
