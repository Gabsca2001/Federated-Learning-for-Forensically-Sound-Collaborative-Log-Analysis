# Implementation plan and acceptance gates

> **Pilot multiobiettivo — 2026-09-30:** quattro ricerche validation-only su un round firmato congelato.
> Obiettivi reconnaissance→benign e degrado generale, gated-composite e TPM-only;
> 66 query per cella, verifiche indipendenti completate. Nel caso untargeted il calo
> selezionato è 0,675 pp con gated e 25,297 pp con TPM-only (soglia predefinita 1 pp).
> Non è evidenza su test o training live; vedere il [report e i grafici](../results/m6-adaptive-objectives-ablation-v1/README.md)
> e il [protocollo](M6_ADAPTIVE_OBJECTIVES_ABLATION_V1.md).


> **Completion update — 2026-09-30:** all four adaptive extension pairs are verified.
> The [five-seed report](../results/m6-adaptive-multiseed-v1/README.md) includes paired endpoints,
> trajectories and admission counts. Selected test ASR is 0/669 in both arms for every seed.
> The mean adaptive-minus-clean macro-F1 difference is +0.4038 pp across all five
> seeds (+0.1367 pp for the four new seeds). These are descriptive outcomes, not
> proof of universal robustness or beneficial poisoning. Earlier running/pending
> statements below are historical. The original locked protocol is unchanged.


> **Historical status snapshot (2026-09-29):** the active-policy five-seed comparison, fixed-signal
> sensitivity, live +10% sensitivity, adaptive frozen pilot, signed smoke and paired
> v4 seed341593 are completed. The four additional adaptive seed pairs are running;
> their completion is recorded in the newer update. See [current result index](../results/README.md)
> and [publication checklist](PUBLICATION_READINESS.md). Dated preparation, stopped,
> pending and running notes below are historical execution records, superseded by
> the later completion/recovery entries. Original locked protocols remain unchanged.

## Planning rule

The project is organized as a sequence of executable acceptance gates. A milestone is
complete only when its generator, verifier, negative cases, and reference runtime evidence
agree. Later milestones may add new artifact types, but they must not silently reinterpret or
rewrite an earlier finalized workspace.

The M1–M8 reference implementation is complete. The table below is therefore both a roadmap
and a map of the evidence currently present in the canonical campaign.

| Milestone | Delivered scope | Acceptance gate | State |
|---|---|---|---|
| M0 — Contract | Package, CLI, YAML contracts, schemas, architecture map | Configuration and schemas load; boundaries are explicit | Complete |
| M1 — Evidence | Acquisition, chain, ECDSA, admission, vault, custody, snapshot | Tampering, wrong identity, expiry, conflicts, and raw/snapshot separation fail closed | Complete |
| M2 — Data | Controlled Data24 ingestion, audit, lineage, windows, split, scaler, central MLP | Deterministic rebuild; no split overlap; training-only scaler; metrics bound by digest | Complete |
| M3 — Federation | 15-client IID/non-IID snapshots, Flower path, auditable FedAvg, PROTEAN | Exact partition coverage; round aggregation reproduced; validation-only selection locked | Complete |
| M4 — Trust | Enrollment, AK/ESK separation, mTLS, Quote appraisal, revocation, TPM adapter | 15/15 `swtpm` gate; nonce replay, wrong pair, altered PCR/log, and revocation rejected | Complete for software-TPM profile |
| M5 — Secure training | Signed contexts/bundles/decisions, replay rules, isolated training, campaign chain, optional in-round composite gate | Original and composite 30-round campaigns verify; all 450 in-round trust/statistical decisions and weighted checkpoints independently recompute | Complete for the local Docker/`swtpm` profile; clean-policy calibration analysis published |
| M6 — Byzantine analysis | Frozen attacks, robust aggregation, joint trust/statistical admission, live disagreement training, independently verifiable live-decision explanations, model/prototype sensitivity, reports | Every method receives the same inputs; all 450 live decisions, explanations, and weighted checkpoints recompute; invalid assumptions fail; reports regenerate | Complete for the controlled local Docker/`swtpm` profiles |
| M7 — Investigation | Predictions, IG/prototype explanations, ATT&CK mapping, deterministic report | Complete digest-valid lineage from report case to controlled source records | Complete for both the original M5 reference and the M6 live-disagreement checkpoint |
| M8 — Preservation | Inventory, Merkle commitment, RFC 3161 time proof, recovery TAR, accounting | Entire chain verified offline; all campaign invariants and final lineage pass | Original and M6-linked reference closures complete |

## Dependency order

```text
M1 artifact rules
 └─> M2 canonical dataset
      └─> M3 partitions and learning
           ├─> M4 identity/attestation
           │    └─> M5 secure campaign
           │         ├─> original M7 investigation chain
           │         └─> M6 robustness experiments
           │              └─> extended M7 investigation chain
           └──────────────────────────┐
                                      └─> M8 preserved closure
```

The completed original M8 package preserves the canonical M2, M3, M4, M5, and six-case M7
chain. A separate completed package closes the extended thesis experiment: it accepts the
signed in-round M6 checkpoint, preserves the 16-case M7 lineage, and reconstructs every
round/client/policy decision from its offline recovery archive. The two closures use distinct
workspaces and identifiers, so neither silently rewrites the other.

## Completed gates

### M1 — forensic artifact semantics

The vertical slice defines canonical manifests, SHA-256 commitments, ECDSA signatures,
identity/attestation-aware admission, idempotency, custody chaining, a content-addressed
vault, and deterministic snapshots. It also establishes the rule that normalized data and
features never overwrite raw evidence.

### M2 — canonical dataset

The completed reference path uses the UWF-ZeekData24 Parquet release. Source bytes are
recorded in a controlled-download manifest; events are consolidated without discarding label
lineage; capture dates remain indivisible across splits; the scaler is fitted on training
only; and the central model's weights and metrics bind the exact dataset and scaler.

The CSV workflow remains a supported earlier profile and must use distinct workspace and
experiment identifiers.

### M3 — clean federation and auditable adaptation

IID and non-IID partition verifiers enforce complete one-client coverage of every training
and validation window while excluding raw-event fields. Every FedAvg round preserves the
actual local updates and can be independently reconstructed. The PROTEAN extension evaluates
its lambda candidates without test access, locks two declared endpoints, and only then
publishes their final test/holdout comparison.

### M4 — trust deployment

The protocol, topology, schemas, adverse cases, and 15-`swtpm` Docker campaign are complete.
Each identity uses distinct AK and ESK roles; Quotes bind one-use nonces and independently
replayed PCR expectations; TLS certificates bind the same enrollment. The physical TPM
adapter and preflight exist, but the separate hardware runtime remains future validation.

### M5 — secure round and campaign

The single-round Docker gate admitted 15/15 TPM ESK-signed bundles and reproduced the stored
FedAvg checkpoint. The chained extension completed 30 rounds, admitted 450/450 contributions,
recorded zero quarantines, and passed independent campaign verification. Validation-only
selection chose round 11 before test evaluation.

The opt-in profile binds the clean-calibrated gated-composite policy before local work
starts. For every round it refreshes/validates M4 evidence, creates the signed context, lets
the isolated clients train and TPM-sign their bundles, applies statistical admission before
aggregation, and independently recomputes the resulting weighted checkpoint. Unit and tamper
tests cover downweighting, idempotent replay, exact aggregation, and modified-update failure.
The clean one-round smoke and separate 30-round campaign are complete. The M6 disagreement
profile reuses this runtime gate with a separately bound treatment contract. Its fresh-baseline
one-round calibration smoke and 30-round container execution are also complete and independently
verified.

### M6 — Byzantine-resilience experiments

M6 freezes verified M5 updates before applying declared attacks. FedAvg, coordinate median,
trimmed mean, Multi-Krum, Bulyan, clipping, and prototype defenses are evaluated under their
explicit `n`/`f` assumptions. Machine-readable results, deterministic figures, and verifier
receipts preserve both successful defenses and failure modes.

The joint-admission pilot compares two ablations (`tpm_only`, `statistics_only`) and two
integrated policies (`sequential`, `gated_composite`) on the same round-11 update population.
Clean-only calibration fixes the statistical and composite thresholds before candidate labels
are evaluated. A controlled 2x2 matrix measures both signal-disagreement directions while
retaining the M5 rule that failed trust is a hard veto.

The contribution-explanation bundle then treats each policy outcome and robust-aggregation
treatment as a forensic event. It reports exact threshold margins, ranked indicator
contributions, named tensor deviations, clip scales, coordinate-retention fractions, Krum
ranks, and client selections. Its verifier recreates all 15 explanations and all six traces
from the frozen inputs; attack labels are excluded from explanation generation.

The live disagreement extension assigns one client to each trust/statistics cell before a round
starts. Its anomalous clients sign a directionally sign-flipped and amplified update with their
TPM ESK, while controlled
trust failures remain explicitly separated from the observed passing `swtpm` evidence. The
gated-composite decision controls the actual aggregation and the other three policies are paired
shadow ablations. The completed 30-round execution recomputed 450/450 decisions. The combined
policies detected all 90 controlled unsafe observations; each single-signal ablation missed 30.
The selected round 11 model reached isolated test macro-F1 `0.924554`. Two of 360 safe
contributions were statistically quarantined and 24 were retained at reduced weight.

A second explanation path covers this full live trajectory rather than one frozen round. It
binds all 450 deployed decisions to their signed bundles, update tensors, checkpoint weights,
exact policy margins, and counterfactual aggregate influence. Its verifier first reconstructs
the campaign and then regenerates the explanation payload and indexes byte for byte. This closes
the gap between the readable live summaries and an independently verifiable explanation
artifact; test data and attack labels remain outside explanation generation.

The separate real post-training PCR profile is now empirically complete. It binds the
intervention into the signed round contract. In round 30, a fresh AK-signed Quote for `client03`
received a verifier-signed `failed_measurement` appraisal; its unchanged probe bundle was TPM
re-signed against that result and quarantined before FedAvg. Independent verification proved
Quote authenticity, the failed measurement, and zero-weight exclusion. This remains separate
from the controlled disagreement matrix and uses a fresh M4 baseline `1.3` workspace.

### M7 — investigation reporting

The original six-case M5 reference resolves 69 events and 81 controlled source records. The
extended thesis run starts from the selected in-round M6 checkpoint and resolves 16
label-independent test cases through prediction, Integrated Gradients, prototype distance,
ATT&CK mapping, and final JSON/Markdown reporting. It binds 811 events and 826 controlled source
records with zero lineage or verification errors. Five mappings are candidate tactics, four are
not applicable, and seven ambiguous multi-tactic cases remain explicitly unresolved. Its public
snapshot is descriptive and deliberately not presented as a performance estimate.

### M8 — preservation closure

M8 inventories 2,381 artifacts and seven external bindings, commits 2,388 leaves under one
Merkle root, obtains a verified RFC 3161 token, writes a deterministic offline recovery TAR,
and reconstructs the 30-round/450-contribution M5 campaign from that package. The final
verifier reports five verified stages and zero errors.

The separate M6-linked closure inventories 3,011 artifacts, commits 3,018 leaves, timestamps
the new root, and exports a 2.49 GiB recovery TAR. Its in-round accounting reconstructs all
450 submissions, 358 contributors, 24 downweights, and 92 quarantines. It binds the observed
450/450 passing M4 admissions, the controlled disagreement contract, the selected round-11
model, and the linked M7 investigation. M8.6 verifies the complete lineage with zero errors.

## Post-M8 work

These tasks can strengthen the thesis or a later production design, but they are not part of
the completed M1–M8 acceptance chain:

- retain the completed M6-linked M8 recovery archive, accounting workspace, final receipt,
  and sanitized thesis-facing result snapshot as the primary experimental closure;
- retain the completed paired five-seed M3 evaluation as the statistical reference;
- retain the verified 13-stage offline M4–M8 overhead receipt as the reference replay result;
- retain the verified three-trial containerized `swtpm`/mTLS/secure-round runtime receipt and
  its sanitized result snapshot as the local runtime reference;
- add a separate multi-host contribution-API experiment before making network-latency or
  failure-recovery claims;
- retain the completed, byte-recomputed UWF-ZeekData22 post-selection evaluation, its separate
  Discovery alignment stress, and their sanitized result snapshot as the external reference;
- retain the verified one-round in-round smoke and the separate 30-round clean campaign; treat
  its 75 downweights and six quarantines as measured clean-run interventions when designing the
  paired policy calibration/attack experiments;
- retain the verified bound live-disagreement campaign and the separately published 30-round
  real-attestation-failure result without overwriting either reference;
- retain the completed frozen round-11 mechanism explanations and the separate 450-decision
  live bundle; extend them only when repeated joint-admission experiments add new sources;
- execute the trust workflow with a physical TPM 2.0 node or fleet;
- move evidence into WORM/object-lock storage with retention and access-control policy;
- define production key custody, rotation, revocation distribution, and disaster recovery;
- test multi-host networking, scale, failure recovery, and service isolation;
- assess privacy mechanisms such as secure aggregation or DP-SGD as separate profiles;
- perform independent security review and reproducibility review.

These extensions must receive new experiment identifiers and must not overwrite the preserved
reference workspaces.

## Active-policy replication acceptance gate (2026-09-25)

The four-campaign one-seed pilot passed. The next gate is 20 verified campaigns:
five paired seeds × two deployed policies × clean/controlled disagreement. Preserve
the four pilot campaigns and add 16 without changing thresholds or attack assignments.
Completion requires per-campaign verification, matching paired inputs, seed-level paired
statistics and sanitized source-bound results. Do not count rounds or client decisions
as independent seeds. The multi-seed gate remains in progress. See
[M6 policy protocol](M6_POLICY_PILOT.md) and [pilot results](../results/m6-active-policy-pilot-v1/README.md).

## Five-seed active-policy gate completed — 2026-09-25

This completion update supersedes the earlier in-progress checkpoints above. All 20
30-round campaigns completed and passed their campaign verifiers (600 rounds, 9,000
contribution decisions). Recovery retained previous artifacts. The final
[report, figures and source-bound tables](../results/m6-active-policy-multiseed-v1/README.md) are available.

Mean test macro-F1: gated/sequential 0.942285/0.939303 clean and
0.939053/0.936771 under controlled disagreement. Paired gated-minus-sequential
95% t intervals include zero in both conditions: [-0.004490, 0.010455] and
[-0.009307, 0.013869]. Superiority is not established. Both exclude 450/450
declared-unsafe contributions per policy, while gated produces more benign
quarantines and downweights. Trust-failure cells remain counterfactual.
Five seed pairs are the statistical units; rounds and contributions are not
independent repetitions. Adaptive attack and threshold/weight sensitivity remain
future gates; the existing M8 closures do not automatically cover these new runs.

## Fixed-signal sensitivity completed — 2026-09-25

[Replay report and figures](../results/m6-policy-sensitivity-replay-v1/README.md): seven predeclared variants across five seeds and
both recorded policy trajectories; 9,000 baseline decisions reproduced and 63,000
variant decisions recomputed. No retraining, test access or configuration selection.
On gated trajectories, downweight threshold +10% reduces clean downweights 366→248
and attacked downweights 196→108 while preserving 450/450 unsafe exclusions.
Quarantine threshold +10% instead retains three unsafe updates at half weight.
These are fixed-signal outcomes, not predictive-performance improvements. Current
policy and frozen experiment inputs are unchanged. Live sensitivity and adaptive
attack validation remain separate future gates.

## Exploratory live sensitivity prepared — 2026-09-25

The [fixed protocol](M6_LIVE_SENSITIVITY.md) tests only the downweight threshold +10% with two
pilot and eight subsequent campaigns, paired against the ten preserved original
gated runs. Config/runner/baseline hashes are frozen; the reference policy is
unchanged. Continuation depends on technical verification, not favorable scores.
Campaign execution is pending. Test results from the standard finalizer will be
exploratory, not independent confirmation after the replay-informed choice.

## Live +10% sensitivity completed — 2026-09-26

Supersedes prior pending recovery notes: all ten new campaigns passed verification.
[Full paired report and four figures](../results/m6-live-downplus10-v1/README.md) compare them with the ten original
gated campaigns. Clean test means: original 0.942285, variant 0.942222; attacked:
0.939053 versus 0.933250. Both paired 95% intervals include zero. Safe downweights
fall 366→242 clean and 196→106 attacked; all 450 unsafe observations per arm remain
excluded in the controlled scenario. The reference remains original gated: the
variant reduces interventions but does not demonstrate predictive improvement.
This replay-motivated experiment is exploratory; adaptive attack validation and
new M7/M8 preservation remain outstanding.

## Adaptive targeted-attack pilot prepared — 2026-09-27

[Threat model, algorithm and execution](M6_ADAPTIVE_ATTACK.md): three colluding clients, targeted
reconnaissance-to-benign gradients over model tensors, projected proposals and exact
gate-feedback backtracking, 66 total queries. Two tests and production source-round
preflight pass, including byte-identical clean aggregation. The search has not yet
run. This privileged white-box frozen-round experiment is not a live signed campaign;
optimization validation is attacker-visible, test access forbidden. No success or
general robustness claim is made. The unexecuted scale-grid draft was superseded.

### Adaptive pilot result — 2026-09-27

The frozen adaptive pilot was executed and independently recomputed (66 queries).
60/64 adaptive proposals were feasible, but selected reconnaissance-to-benign ASR
and ASR gain were both zero. Selected validation macro-F1 decreased by 1.019
percentage points. See `results/m6-adaptive-frozen-pilot-v1/README.md` for all
attempts, figures and limitations. This is not a signed live attack result;
live integration remains in progress.

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

## Untargeted adaptive four-seed extension — completed 2026-10-03

Four matched arms (gated-composite clean/adaptive and TPM-only clean/adaptive) completed 30 verified rounds on each of seeds 342593–345593, for 480 secure rounds total. The [published report and comparison figures](../results/m6-adaptive-untargeted-multiseed-v1/README.md) passed manifest and source-receipt checks; the [detailed analysis](M6_ADAPTIVE_UNTARGETED_MULTISEED_RESULTS_V1.md) records per-seed outcomes and limitations.

Mean clean-minus-adaptive selected-checkpoint test macro-F1 loss was 0.000552 for gated-composite and 0.013886 for TPM-only. These are descriptive results, not a significance test or independent-dataset generalization. Seed 342593 was exploratory and its result was known before the other three replications were planned; the TPM-only adaptive checkpoint for that seed was selected at round 10, before the attack began in round 11. The three later seeds show no consistent predictive-performance advantage. Earlier launch and in-progress entries remain historical records; the locked protocol was not changed.
