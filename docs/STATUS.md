# Implementation status

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

## Summary

The deterministic M1–M8 implementation and the current local-test reference chain are
complete and verified end to end. A joint M4/M6 admission pilot now compares four policies
and both trust/statistics disagreement directions on verified round-11 inputs. A separately
verified frozen-round bundle explains all 15 contribution decisions and six aggregation
mechanisms without using attack labels. A second independently verifiable bundle reconstructs
the 450 decisions that drove the live M6 trajectory. The same gated-composite policy is now
implemented as an opt-in M5
in-round gate over newly trained, TPM-signed updates. Its unit/tamper checks, one-round smoke,
and separate 30-round/450-contribution clean campaign all verify. The full run selected round
25 and exposed 75 clean downweights plus six clean quarantines, now published for calibration
analysis. The live M6 disagreement profile has also completed its fresh-baseline smoke and
30-round campaign: 450/450 decisions and all weighted checkpoints independently recompute,
the combined policies detect 90/90 controlled unsafe contributions, and the deployed model
reaches isolated test macro-F1 `0.924554`. That selected checkpoint has now completed a fresh
16-case M7 prediction-to-report chain, resolving 811 events and 826 controlled source records
with all four verifiers passing. Its independent M8 closure is now complete: 3,011 payload
files, 3,018 Merkle leaves, an RFC 3161 anchor, a 2.49 GiB offline package, all 450 in-round
submissions reconstructed, and final lineage verification passed. The paired five-seed M3
evaluation and the 13-stage M4–M8 offline-overhead reference execution are complete, verified,
and published as sanitized snapshots. The separate three-trial M4/M5 containerized-runtime
benchmark is also complete,
verified, and published. The isolated UWF-ZeekData22 evaluation and its two-burst Discovery
alignment stress are complete, independently recomputed, and published. The real post-training
TPM-failure profile has now also completed 30 rounds: an authentic non-conforming Quote caused
one hard trust quarantine and zero FedAvg weight, with the independent verifier passing. Other
principal gaps are physical-TPM and multi-host/API benchmarks, and production-grade evidence
storage and key management.

The M6 live-disagreement implementation now has empirical runtime evidence. It binds the four
controlled trust/statistics cells before training, makes anomalous clients TPM-sign their
transformed update, and applies the composite decision before FedAvg. The observed `swtpm`
appraisals pass; the failed-trust cells remain explicitly labelled counterfactual policy inputs.
The separate real-failure path is empirically complete. It used a fresh post-training challenge
and an authentic AK-signed Quote over an actually extended `swtpm` PCR. M4 issued the signed
`failed_measurement` result; M5/M6 failed only `fresh_attestation`, skipped statistical scoring,
and excluded `client03` before FedAvg. The run selected round 25 and achieved isolated test
macro-F1 `0.935467`; the intervention was in round 30, so this selected metric demonstrates
continuity but not the general utility cost of trust failures.

## Current coverage

| Component | State | Current assurance |
|---|---|---|
| Canonical manifests and SHA-256 commitments | Implemented | Integer-safe canonical profile; deterministic and tamper-tested |
| ECDSA P-256 signing | Implemented | Software authorities plus TPM ESK adapter; key roles remain explicit |
| Acquisition, batch chain, and custody | Implemented | Atomic local publication and chained events; production WORM storage not implemented |
| Admission and idempotency | Implemented | Identity, content, chain, signature, attestation status/expiry, replay semantics |
| Content-addressed evidence vault | Implemented | Tamper-evident prototype; object lock and retention service remain external |
| UWF-ZeekData24 controlled ingestion | Implemented (M2) | Canonical Parquet manifest covers seven source partitions and their sizes/digests |
| Deterministic normalization/windowing | Implemented (M1–M2) | Frozen 25-feature, 60-second contract; source/event/window lineage verified |
| Group/time split and training-only scaling | Implemented (M2) | Capture-date groups are disjoint; final capture reserved; scaler provenance checked |
| Central MLP baseline | Implemented and verified (M2) | Validation macro-F1 `0.945674`; test macro-F1 `0.923073` |
| 15-client IID/non-IID partitioning | Implemented and verified (M3) | Exact train/validation/local-test coverage; client and server test artifacts are isolated from training access |
| Flower ClientApp/ServerApp | Implemented (M3) | Current Message API; 15-client full-participation FedAvg profile |
| Auditable FedAvg runner | Implemented and verified (M3) | All training precedes test access; aggregation, local-only inference, and post-selection per-client tests are independently reconstructed |
| Paired multi-seed FedAvg evaluation | Implemented and verified (M3) | Five seeds spaced by 1000; 10/10 sources verified; pooled test macro-F1 `0.9387` IID and `0.9414` non-IID; paired delta interval includes zero; client-local and local-only distributions published |
| External UWF-ZeekData22 evaluation | Implemented and verified (M5 extension) | 10,128 windows; binary attack F1 `0.0863`; shared-label macro-F1 `0.4968`; reconnaissance recall `0`; strong frozen-scaler feature shift; predictions and metrics byte-recomputed |
| Data22 Discovery alignment stress | Implemented and verified (M5 extension) | 2 independent bursts, 2,086 events, 12 correlated offsets; at least one segment detected in 24/24 burst-offset trials; every segment in 19/24; zero offset reproduces the primary result |
| PROTEAN adaptation | Implemented and verified (M3 extension) | Four validation-only lambda candidates; two endpoints locked before test access |
| Enrollment, AK/ESK separation, challenge, revocation | Implemented (M4) | Signed one-to-one bindings and append-only revocation semantics |
| Quote/PCR appraisal and Attestation Result v2 | Implemented (M4) | One-use nonce and independent PCR replay; preserved baseline gate and fresh in-round baseline `1.1` smoke appraisal both passed 15/15 |
| TLS 1.3 mutual authentication | Implemented (M4) | EKU, SAN, enrollment-fingerprint, and wrong-pair checks |
| Physical TPM adapter | Implemented; runtime pending | Same `tpm2-tools` interface via `device:/dev/tpmrm0`; no hardware result claimed |
| Secure FedAvg campaign | Implemented and verified (M5) | New campaigns bind post-selection client-local metrics; preserved reference has 30 rounds, 450/450 bundles, and selected round 11 |
| In-round composite admission | Implemented, runtime-integrated, and verified | Fresh 30-round campaign; 450/450 decisions recomputed; 369 accepted, 75 downweighted, six quarantined; selected round 25; isolated test macro-F1 `0.935467` |
| Byzantine/robust aggregation experiments | Implemented and verified (M6) | Frozen real M5 inputs; model/prototype campaigns; joint TPM/statistical admission; controlled 2x2 disagreement matrix; 15 contribution explanations and six aggregator traces |
| Live TPM/statistical disagreement experiment | Implemented and verified (M6) | Fresh 30-round campaign; 450/450 decisions recomputed; combined policies detect 90/90 controlled unsafe contributions; two safe quarantines; selected round 11; isolated test macro-F1 `0.924554` |
| Live contribution-decision explanation bundle | Implemented and independently verified (M6) | 30 rounds and 450/450 slots; exact trust/policy margins, tensor drivers, retained FedAvg weight, influence, and counterfactuals recompute without test data or attack labels |
| Real post-training TPM failure | Implemented, runtime-integrated, and verified (M4/M6) | Baseline-`1.3`, 30 rounds, 450 submissions; one authentic `failed_measurement`, one trust quarantine, target weight zero and exclusion independently verified; selected test macro-F1 `0.935467` |
| Investigation chain | Implemented and verified (M7) | Original M5 reference: six cases/69 events/81 records; M6-linked extension: 16 cases/811 events/826 records; both prediction-to-report lineages complete |
| Preservation inventory | Implemented and verified (M8.1) | Original: 2,381 artifacts; M6-linked thesis closure: 3,011 artifacts and seven external bindings |
| Merkle commitment | Implemented and verified (M8.2) | Original: 2,388 leaves; M6-linked thesis closure: 3,018 leaves; deterministic duplicate-last rule |
| Trusted timestamp | Implemented and verified (M8.3) | RFC 3161 token over the M8 Merkle root; offline verification succeeds |
| Offline recovery export | Implemented and verified (M8.4) | Deterministic TAR; M6-linked closure has 3,011 payload and 11 assurance entries |
| Campaign invariant accounting | Implemented and verified (M8.5) | Both profiles reconstruct 30 rounds × 15 clients; in-round profile also verifies policy treatments, 358 contributors, 24 downweights, and 92 quarantines |
| Final preservation verification | Implemented and verified (M8.6) | Original and M6-linked chains; five assurance stages; offline inputs only; zero errors |
| Offline verification-overhead benchmark | Implemented and verified | 13/13 stages, 45 measured samples, 13 source snapshots, zero errors; receipt `overhead-benchmark-242c9f91b96d5b8fad17acff`; no runtime/TPM claim |
| Containerized runtime-overhead benchmark | Implemented and verified | Three fresh M4/M5 trials; 36/36 stages; median secure-round span `105.980 s`; direct ESK signature `13.854 ms`; receipt `runtime-overhead-adb5811cce9ded407e4b1e0d` |

## Canonical reference chain

The original M5-based reference remains preserved by its completed M8 package. The M6-linked
thesis experiment is closed by a second, independent package and is the primary extended
experimental chain.

| Stage | Workspace or identifier |
|---|---|
| M2 dataset | `artifacts/m2-data24-parquet` |
| M3 IID partitions | `artifacts/m3-data24-parquet-iid-local-test-v1` |
| M4 trust | `artifacts/m4-trust-local-test-v1` |
| M5 campaign | `artifacts/m5-secure-multiround-local-test-v1` |
| M7 report | `artifacts/m7-investigation-report-test-first6-local-test-v1` |
| M8 inventory | `m8-preservation-ef926a6449b257ad9602bb5a` |
| M8 Merkle tree | `m8-merkle-tree-97e2d8a71d5b1ef11fb6c91c` |
| M8 timestamp | `m8-timestamp-anchor-88a57203d1340ff4892778e1` |
| M8 recovery | `m8-recovery-export-76702dfab9ac61350f18b31c` |
| M8 accounting | `m8-campaign-accounting-754be120eb3082973ded38af` |
| M8 final receipt | `m8-final-verification-18a7463101b543b5f97df3f1` |
| Offline-overhead receipt | `overhead-benchmark-242c9f91b96d5b8fad17acff` |
| Runtime-overhead receipt | `runtime-overhead-adb5811cce9ded407e4b1e0d` |
| Data22 external evaluation | `m5-external-generalization-8ba28d267facbc1f91af7948` |
| Discovery alignment stress | `m5-discovery-stress-d4a3898efbb5682c01d4ffa2` |

| Extended thesis stage | Workspace or identifier |
|---|---|
| M6 live disagreement campaign | `artifacts/m6-trust-statistical-disagreement-local-test-v1` |
| M6 live decision explanations | `artifacts/m6-live-contribution-explanations-local-test-v1` |
| M6-linked M7 report | `artifacts/m7-investigation-report-m6-disagreement-test-first16-local-test-v1` |
| M6-linked M8 inventory | `m8-preservation-e7e01dfefa1dfb07bddd7fef` |
| M6-linked M8 Merkle tree | `m8-merkle-tree-88109448b5da654b7124d218` |
| M6-linked M8 timestamp | `m8-timestamp-anchor-1a4cceb5a6de79502f2cf0f2` |
| M6-linked M8 recovery | `m8-recovery-export-d70949e9c95d458578d07428` |
| M6-linked M8 accounting | `m8-in-round-campaign-accounting-c38e5feea19c1e9d11b94b48` |
| M6-linked M8 final receipt | `m8-in-round-final-verification-67924c5247b31fce59ae5080` |

The final assurance state is
`merkle-committed-time-anchored-recovery-exported-campaign-accounted-finally-verified`.

## Important boundaries

- The RFC 3161 timestamp anchors the M8 preservation root. It does not convert the local M1
  custody-event store into a continuously externally anchored production ledger.
- `swtpm` confirms protocol and artifact behavior but is not equivalent to hardware-backed
  key non-exportability.
- The M8 recovery package preserves the selected reference chain; it is not a substitute for
  an organizational retention, access-control, backup, or legal-admissibility policy.
- The temporal holdout is benign-only and cannot support a multiclass generalization claim.
- The five-seed M3 summary verifies 10/10 source runs. Its intervals describe this fixed
  dataset and protocol; they do not establish external-dataset generalization.
- The completed Data22 run is evidence of poor cross-dataset transfer for one frozen checkpoint,
  not universal performance. Its official CSV subset has narrower tactic coverage than the full
  Parquet release, and nearly every row exceeds an absolute scaled feature value of five.
- The Discovery alignment result has only two independent temporal bursts. Its 24 burst-offset
  trials reuse events and support binary burst-detection sensitivity only, not an independent
  sample estimate, open-set Discovery classification, or confidence interval.
- Earlier M2 seed diagnostics used a separate partial-fit monitoring protocol. They are useful
  sensitivity evidence but do not substitute for repetitions of the canonical M3 protocol.
- Model explanations and ATT&CK mappings are interpretive, not proof of attacker intent.
- The preserved joint-admission pilot uses real verified update statistics, but its attacked M6 bytes
  are controlled derivations not re-signed as new M5 bundles. Its failed-trust 2x2 cells are
  explicit counterfactual policy controls, not observed M5 admissions.
- The in-round implementation removes the retrospective-only limitation. Its clean one-round
  smoke verifies integration, while the separate 30-round campaign measures the actual training
  trajectory. Because that full campaign has no injected attack, its 75 downweights and six
  quarantines are compatibility costs/false interventions, not evidence of Byzantine detection.
  The live profile signs anomalous updates inside the client and its 30-round result is verified.
  Its failed-trust cells remain labelled counterfactuals rather than observed Quote failures;
  all 450 observed appraisals passed. TPM-only, statistics-only, and sequential are shadow
  decisions, while gated-composite alone controls this model trajectory. Each evidentiary run
  used a fresh M4 baseline `1.2`. The new real-failure implementation requires baseline `1.3`;
  restarting historical TPM state cannot establish either measured-code identity.
- Contribution-decision explanations reconstruct configured policy and aggregator mechanics;
  they are derived interpretations, not primary Zeek evidence or proof of malicious intent.
- The overhead reference is warm-process offline replay under WSL2. Nested verifiers overlap,
  M8 stages have one observation each, and no live `swtpm`, network, or physical-TPM latency
  is claimed.
- The runtime profile measures the current local Docker/`swtpm` prototype. Its M5 client stage
  includes container scheduling, training, validation, serialization, ESK signing, and writes
  through bind-mounted submission directories; it cannot establish WAN/API or physical-TPM
  latency.
- The real-attestation result covers one `swtpm` client and one late failure in one deterministic
  campaign. Its selected checkpoint precedes the failure. Earlier/repeated failures, multiple
  seeds, and a physical TPM are required before estimating a general utility or latency effect.

## Outstanding validation and engineering work

1. Run the M6 multi-seed and threshold/weight ablation experiments over complete live campaigns.
2. Add the adaptive attack as a separate scenario without overwriting the clean or disagreement
   references.
3. Run the M4 adapter against a physical TPM 2.0 host and document the hardware evidence.
4. Store retained packages in WORM/object-lock storage and define the production key lifecycle.
5. Validate service separation, multi-host performance, and failure recovery outside the research
   deployment.

See [Implementation plan](IMPLEMENTATION_PLAN.md) for milestone gates and
[Architecture](ARCHITECTURE.md) for the trust and claim boundaries.

## Active-policy extension — checkpoint 2026-09-25

- Implemented opt-in sequential admission controlling real aggregation, with the same
  mandatory integrity/TPM veto. The default remains gated_composite. Checkpoint verification
  binds the recorded aggregation strategy; the prior implementation digest remains supported.
- Four one-round smoke campaigns and four 30-round seed-341593 pilot campaigns verified.
  Exact pilot results and limits: [sanitized snapshot](../results/m6-active-policy-pilot-v1/README.md).
- Four additional seeds (342593, 343593, 344593, 345593) are running as 16 new campaigns,
  using seed-specific CPU configs and paired IID partitions. The runner now accepts
  `--federation-config`; code/config and pilot manifest hashes are frozen in the experiment lock.
- At this checkpoint the first 12 extension campaigns verified. The final seed's clean
  gated campaign completed and passed its internal verifier; a Docker Hub metadata timeout
  interrupted the additional verification build. The build retry succeeded, and targeted
  recovery is running. Full five-seed completion and statistical conclusions remain pending.
- Targeted validation: 21 tests passed for the runner, secure-round and disagreement paths;
  shell syntax, static checks and experiment preflight passed. This is not a new claim that
  the entire test suite was rerun after the runner extension.

Protocol, commands and recovery details: [M6 policy pilot](M6_POLICY_PILOT.md).

### Recovery update — 2026-09-25

The targeted recovery verified the final seed's gated/clean, gated/disagreement and
sequential/clean campaigns. Total completed: 19/20 including the pilot. The last
sequential/disagreement campaign stopped before client01 provisioning because Docker
exhausted its default network address pools. No training began and node directories
were empty. Removed only the unused smoke gated/clean bridge after confirming it had
no attached containers; retained every TPM volume and artifact. The incident-specific
root script `resume_m6_policy_last.sh` resumes provisioning in the existing namespace
and then runs/verifies the last campaign. Final five-seed charts and statistics remain
pending completion; no missing result is imputed.

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

### Pilot verification recovery — 2026-09-25

Both seed-341593 downplus10 campaigns completed training. Clean passed the additional
verification; disagreement passed its internal campaign verifier, then the additional
verification build failed on a Docker Hub metadata timeout. The build retry succeeded
and verification-only replay was restarted against the existing artifacts. No training
or provisioning was repeated. Final recovery confirmation is pending.

### Pilot recovery completed — 2026-09-26

The disagreement verification completed all 30 rounds and final campaign verification
with zero errors (selected round 11; 19 downweights; 92 quarantines). Both pilot
campaigns are now verified. Restored the completion marker after checking the logs;
stopped only the recovered campaign TPM containers and removed its empty bridge.
Volumes and artifacts were retained. The remaining eight campaigns are ready, not
yet launched by this recovery.

### Remaining-seed recovery — 2026-09-26

Seeds 342593, 343593 and 344593 passed both conditions (six campaigns). Seed
345593 clean completed 30 rounds and internal verification, then Docker Hub
metadata resolution timed out before additional verification. The last attacked
campaign has not started. Root script resume_m6_downplus10_345593.sh verifies
the existing clean campaign, then provisions/runs only the untouched attacked
campaign. It preserves frozen scripts, configuration, volumes and artifacts.
Completion of these last steps is pending; do not repeat earlier training.

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

### Second invocation correction — 2026-09-29
The first recovery preserved the seed argument but passed a relative script path. Path(__file__).relative_to(ROOT) then failed before writing the pair lock or starting training. The pair directory was confirmed empty. Separate recovery v2 passes the absolute runner path through the unchanged numerical wrapper. Its exclusive process guard and original input lock checks remain; it removes only the empty pair directory with nonrecursive rmdir, refusing any contents. A subprocess probe verified absolute __file__, preserved seed argument and numerical runtime before launch. Original scripts, locks, receipts and logs remain unchanged. Recovery v2 launched as PID 2305906; active log m6-adaptive-multiseed-v1-recovery2.log. See scripts/recover_m6_adaptive_multiseed_invocation_v2.py and artifacts/m6-adaptive-multiseed-v1-invocation-recovery2.json.

## Untargeted adaptive M6 follow-up — seed 342593

This new four-arm experiment uses the pre-specified protocol in
M6_ADAPTIVE_UNTARGETED_LIVE_V1.md. The first launch verified 93/120
arm-rounds before Docker Desktop exhausted its runtime mount table during
client signing in gated_adaptive round 24. The error was diagnosed as a
100,000-mount kernel limit at 99,938 active mounts, not data-disk exhaustion.
The temporary runtime cap is 200,000; TPM containers and original artifacts
were preserved.

As of 2026-10-01, the strict resume preflight has revalidated the signed
query-32 selection and replayed all 66 validation queries with no test access.
Continuation is pending launch; no new experiment outcome is claimed. See
M6_ADAPTIVE_UNTARGETED_RESUME_S342593_V1.md for the exact partial state,
recovery script and receipts.

The guarded continuation subsequently launched as PID 3254152 after all
scientific lock hashes matched. At the latest process check it was signing the
missing client05 submission for gated_adaptive round 24. The execution log is
m6-adaptive-untargeted-paired-v1-resume2.log; the earlier preflight and
lock-guard failures remain in separate preserved logs. No new round result is
claimed until its independent verifier passes.

The first continuation process exited before producing a signature: its Docker
service did not receive the M5 workspace environment, so /campaign/public was
not mounted. This is isolated to the recovery wrapper. The failed attempt log
and receipt are preserved; staging is empty, no campaign submission changed,
and all 15 TPMs are healthy. The wrapper now passes the frozen runner's M5
workspace variables and will use a new attempt log and receipt.

The continuation then stopped at the M5 context-validity gate. The signed
gated_adaptive round-24 context expired at 2026-10-01T03:50:38Z; the signer
rejected it and created no client05 signature or aggregation checkpoint.
Changing the context or bypassing validation would break its signed selection
binding, so the wrapper will not be retried. The original workspace remains
preserved with 93 verified arm-rounds, a partial gated_adaptive round 24, and
the two TPM-only round-24 arms not yet run. All 15 TPMs are healthy and unchanged.
Any next attempt requires a separate workspace/branch and an explicit
plan-aware decision about reusing verified rounds or repeating the campaign.
No result is claimed from this incomplete run.

The latest and terminal recovery attempt was PID 3255590, logged in
m6-adaptive-untargeted-paired-v1-resume3.log. It reached the signer with the
correct M5 mount, but the signed round context had expired. The signer rejected
it before producing a TPM signature. The two process receipts are stale; process
inspection found no active recovery/signing worker. Only the 15 persistent,
healthy TPM containers remain.

## Untargeted adaptive four-arm M6 campaign — verified 2026-10-01

The v3 continuation branch at `artifacts/m6-adaptive-untargeted-paired-s342593-v1-continuation-v3/` completed with status `verified`: all four arms have 30 verified rounds (120 total). It preserves 93 previously verified rounds and rebuilds the expired gated-adaptive round 24 from a fresh signed M5 context. The final M5 campaign finalization and verification passed for all arms. The launcher exited and stopped its TPM containers. This section supersedes the pending/interrupted status entries above; they remain as execution history.

Selected-checkpoint test macro-F1 was 0.962488 (gated clean), 0.962301 (gated adaptive), 0.957628 (TPM-only clean), and 0.904285 (TPM-only adaptive). The clean-minus-adaptive loss was 0.000187 for gated-composite and 0.053343 for TPM-only, a difference of 0.053156. The prespecified 0.01 practical threshold was exceeded only by TPM-only in this seed. This is a descriptive single-seed result, not evidence of statistical significance or general robustness.

The report and three comparison figures are in `results/m6-adaptive-untargeted-paired-s342593-v1-continuation-v3/`; its manifest hashes were checked. The report summarizes already finalized evaluation artifacts and does not rerun the test evaluation. See `docs/M6_ADAPTIVE_UNTARGETED_CONTINUATION_S342593_V3.md`.

## Interpretation of the adaptive rounds

The attack is active in rounds 11–30. The frozen search-success rule requires a feasible selected proposal to lower all-class validation macro-F1 by at least 0.01 against that round's clean control. This flag was true in 19/20 TPM-only adaptive rounds and 4/20 gated-composite adaptive rounds. Mean validation macro-F1 over rounds 11–30 was 0.6078 for TPM-only and 0.9344 for gated-composite. Across the clean and adaptive arms (900 decisions per policy), gated-composite recorded 714 accepted, 159 downweighted and 27 quarantined contributions; TPM-only accepted all 900.

Checkpoint timing matters when reading the held-out scores: TPM-only adaptive selected round 10, immediately before the attack starts, whereas gated-composite adaptive selected round 30. Therefore the TPM-only test score is from an unpoisoned pre-attack checkpoint. The large clean-minus-adaptive test gap reflects that validation-based selection fell back to this earlier checkpoint after later attacked rounds had poor validation performance; it is not evidence that the selected TPM-only checkpoint contains a successful poisoned update. This distinction and the single-seed scope should be retained in thesis claims.
## Untargeted adaptive seed extension planned - 2026-10-01

The verified seed-342593 live campaign now has an attacker-versus-benign admission
breakdown documented in [its continuation record](M6_ADAPTIVE_UNTARGETED_CONTINUATION_S342593_V3.md).
Three additional seed replications (343593-345593) are specified in
[M6 adaptive untargeted replication v1](M6_ADAPTIVE_UNTARGETED_REPLICATION_V1.md).
This is an outcome-aware exploratory extension on the same dataset, not a
confirmatory or independent-dataset study.

## M6 untargeted seed 343593 infrastructure recovery

The first launch stopped before enrollment/training due to Docker subnet exhaustion.
The documented infrastructure-only recovery reused the 15 healthy TPMs on a
separate internal subnet; M4 enrollment and mTLS passed. The four-arm 30-round
campaign is now running under the unchanged seed-specific lock. See
[M6 seed-343593 recovery record](M6_ADAPTIVE_UNTARGETED_RECOVERY_S343593_V1.md).


## Untargeted adaptive M6 four-seed extension — completed 2026-10-03

The four matched arms (`gated_clean`, `gated_adaptive`, `tpm_clean`,
`tpm_adaptive`) completed 30 verified rounds on each of seeds 342593–345593
(480 secure rounds total). The final [multi-seed report and comparison figures](../results/m6-adaptive-untargeted-multiseed-v1/README.md)
passed manifest and source-receipt hash checks. Mean clean-minus-adaptive selected
test macro-F1 loss was 0.000552 for gated-composite and 0.013886 for TPM-only;
the seed-level difference was descriptive only and was strongly influenced by
the exploratory 342593 TPM-only checkpoint selected before attack onset. The
three later seeds show no consistent predictive-performance advantage. See the
[detailed results and limitations](M6_ADAPTIVE_UNTARGETED_MULTISEED_RESULTS_V1.md).
The locked protocol documents remain unchanged.
