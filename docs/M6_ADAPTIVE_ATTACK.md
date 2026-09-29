# Adaptive targeted attack: implementation pilot

Executed and independently recomputed on 2026-09-27. All 66 queries matched byte
for byte. The targeted success criterion was not achieved. See
[the complete result](../results/m6-adaptive-frozen-pilot-v1/README.md).
The earlier unexecuted sign-flip scale-grid draft was replaced before any run.

## Research question

Can three valid, colluding clients produce updates admitted by the original
gated-composite policy while increasing classification of reconnaissance as benign?
Admission alone is not damage; a failed attack is a valid outcome, not a reason
to change the protocol after observing the result.

## Threat model and algorithm

The controlled source is seed 341593, clean original gated round 11. Attackers
client02, client05 and client14 control their update tensors, not identity, signatures,
trust appraisal, policy thresholds, labels in the source evidence or sample counts.
For this white-box stress test they know all frozen updates, the coordinator's exact
validation data, calibration and gate responses. This is privileged oracle access,
not a claim that isolated deployed clients possess it. It is not a mathematical
upper bound: the finite heuristic may fail to find existing attacks.

The optimizer differentiates target-class cross-entropy through the current aggregate
on validation reconnaissance rows, taking a direction that increases benign probability.
It perturbs all trainable tensors of the three clients and projects each perturbation
onto an L2 ball centered on that client's original update. Radius is relative to that
client's clean update-delta norm. Four declared restarts use radii 0.25, 0.5, 1 and 2,
with 16 proposals each. Every proposal receives the exact gate decision, recomputing
cohort medians, geometry, individual validation impact, all policy scores and the
actual weighted aggregate. This accounts for changes to honest-client decisions too.

A feasible candidate retains all three attackers and at least the configured minimum
contributors. On improvement in targeted ASR, or lower target cross-entropy at equal
ASR, the state advances and the step grows by 1.25, capped at radius. Otherwise the
state stays unchanged and step halves, floored at 0.0001. The direction is recomputed
at the retained aggregate. Targeted ASR and loss are optimization feedback, not an
independent evaluation. Rejected candidates, parent links and step sizes are retained.

The 66-query budget includes one exact clean control, one fixed sign-flip ×15 control
and 64 adaptive proposals. Controls are excluded from adaptive selection. The winner
maximizes feasible targeted ASR, then minimizes targeted loss, then prefers the earliest
query. Success requires at least +0.10 absolute ASR over the clean aggregate on the
optimization validation rows. Pooled macro-F1 degradation is a secondary descriptive
metric. No test or temporal-holdout file is opened; no favorable outcome is guaranteed.

## Evidence boundary

This is an adaptive optimization experiment on a verified frozen round, not yet a
30-round adaptive runtime campaign. Derived candidate bytes are explicitly not new
TPM-signed submissions. Original signed inputs are verified and unchanged; valid trust
is held fixed to isolate the statistical gate. A live conclusion requires integrating
the treatment before client signing and letting subsequent rounds evolve. Do not
present a frozen oracle success as a signed live compromise or generalization result.

The validation set is deliberately visible to this strong attacker and is used both
by the gate and objective. Any success there is optimization-set success, with possible
overfitting. The class target matches the existing model-replacement objective but
no separate holdout is used here. This pilot checks attack feasibility/mechanics; live,
multi-seed and independent-evaluation gates remain outstanding.

## Execution

From the repository root with the virtual environment active:

```bash
python scripts/run_m6_adaptive_frozen.py run
python scripts/run_m6_adaptive_frozen.py verify
```

The first command refuses an existing output directory. A failed partial workspace
is preserved for investigation, never deleted automatically. The second command
reconstructs the source round and reruns the complete search, comparing every stored
candidate, aggregate, decision record and summary byte for byte. It rejects unexpected
or missing JSON artifacts. Verification does not trust the selected result to guide
the search. Runtime versions are bound to a separate preparation lock; repeatability
outside the current numerical environment remains a separate check.

Artifacts are under artifacts/m6-adaptive-frozen-pilot-v1. Each query preserves the
three submitted candidate models, aggregate if enough contributors remain, all client
scores/decisions and query state. The final summary records source/code/config digests,
control outcomes, selected query, objective gain and the declared success criterion.
No original artifact is modified. The helper action `check` verifies just the source
and reproduces the clean aggregate without creating output.

After run and verification complete, publish sanitized query-budget/ASR and gate-margin
plots, accepted/rejected attempt counts, macro-F1 effects and a detailed result narrative.
Only then define and test the signed live integration. Keep the original gated reference.

## Verified outcome and live implementation status

Of 64 adaptive candidates, 60 met feasibility. Selected query 47 (zero-based)
had targeted ASR 0, gain 0, and validation macro-F1 decrease 0.010194637626025682.
The finite search failed its declared targeted objective. Source files and the
negative result remain unchanged. CSV, PNG/PDF and hashed report inputs are in
`results/m6-adaptive-frozen-pilot-v1/`. Live integration is under implementation;
no signed adaptive campaign has yet been executed or verified.

## Live integration smoke — 2026-09-28

Implemented `scripts/m6_adaptive_live_search.py`,
`scripts/m6_adaptive_live_signing.py`, and
`scripts/run_m6_adaptive_live_smoke.py`. Seven focused tests pass. A separate
read-only compatibility run reproduced all 66 reference queries, candidate tensors,
statistical decisions and aggregates byte for byte using the live search engine.

The fresh smoke campaign is `artifacts/m6-adaptive-live-smoke-v1`, with separate
trust and node directories. Its local log is `m6-adaptive-live-smoke-v1.log`.
Execution has started; no completion or live attack success is claimed yet.
The runner refuses existing evidence and uses the existing M4 provisioning,
attestation, M5 initialization, admission and verification procedures.

Before local training, the coordinator signs a separate precommit binding the
round context, attack settings, validation digest and additional script digests.
Original TPM-signed proposals are preserved. Search checks those proposals without
consuming replay slots. The selected attacker tensors receive new TPM signatures,
with metrics binding the selection, search receipt and original proposal.
Honest proposals are copied unchanged into final submissions. The actual admitted
aggregate must match the optimizer's predicted aggregate byte for byte.
The full search is then independently recomputed.

This is a single-round integration test from the initial model, not the previous
round-11 frozen experiment and not a thirty-round efficacy result. No test split is
used. The additional adaptive scripts are bound by the coordinator precommit;
they are not added to the historical M4 PCR baseline. The baseline itself is
unchanged. Software unit tests cover authorization signatures and tampering;
they do not replace end-to-end TPM verification.

### Live smoke recovery — 2026-09-28

The v1 smoke stopped after all 15 attestations passed and M5 initialized, before
proposal training. The coordinator precommit attempted to canonicalize float-valued
attack settings; canonical signing deliberately rejects floats. The fix binds the
exact derived JSON configuration as a string in the signed core. A regression test
now covers this case; eight focused tests pass.

The failed v1 artifacts and log are preserved. Recovery runs via
`scripts/recover_m6_adaptive_live_smoke_v2.py` into the fresh
`artifacts/m6-adaptive-live-smoke-v2` campaign, reusing only the existing v1 nodes
and trust namespace with refreshed attestations. Its log is
`m6-adaptive-live-smoke-v2.log`. The v1 round is not resumed or backdated.
The v2 run has started; its end-to-end result is still pending.

### Live adaptive smoke independently verified — 2026-09-28

The v2 one-round smoke and independent signed-provenance/search verifier passed.
Three adaptive contributions were newly TPM-signed; actual and predicted aggregates
match exactly. Optimization-validation ASR: 0 to 1; macro-F1: 0.342901 to 0.107455.
This is round 1, one seed, a weak initial baseline and privileged validation access;
no test access or 30-round efficacy claim. See `results/m6-adaptive-live-smoke-v2/README.md`
for figures, all queries and limitations. TPM containers are stopped; evidence is retained.

### Paired adaptive multiround protocol — 2026-09-28

Prepared two 30-round arms at seed 341593: clean and adaptive in rounds 11–30,
66 queries per attacked round, original gated policy. Nine focused tests and
undefined-name checks pass. Test evaluation follows completion of both trajectories.
See `docs/M6_ADAPTIVE_MULTIROUND.md` and `configs/m6-adaptive-paired-s341593-v1.json`.
No multiround attack outcome is claimed before execution and verification.

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
