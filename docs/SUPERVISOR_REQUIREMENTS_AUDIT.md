## Independent multi-trigger validation and thesis revision — 4 November 2026

The frozen 119-file containment profile was evaluated on six new seed/identity assignments, with 24 planned active histories. Twenty-two finish; two original-head attack controls stop on unsupported context/quorum. All 1,180 adaptive queries and 346 selected aggregates replay from retained originals, and 2,693 fixed-input removal certificates pass. The paired clean utility budget passes (maximum macro-F1 loss about 1.7244 percentage points), but new non-IID cases break a general ASR-elimination claim: the bounded complete trigger reaches about 99.495% peak and remains about 46.887% at the last endpoint in one case. No defense retuning or default deployment occurred. The norm theorem is not an ASR theorem.

The actual English LaTeX sources have now been revised with a guarded backup/diff, compiled and visually checked. Earlier notes that the thesis was unchanged describe their historical milestones. Original PDFs remain preserved; the revised PDF is a separate review artifact. ToN-IoT remains explicitly deferred. See [INDEPENDENT_CONTAINMENT_VALIDATION.md](INDEPENDENT_CONTAINMENT_VALIDATION.md) and [SUPERVISOR_REQUIREMENTS_AUDIT_20261104.md](SUPERVISOR_REQUIREMENTS_AUDIT_20261104.md).

> Final formal correspondence, 2026-11-03: a concrete graph-identity defect was
> found and corrected. Replayed/borrowed identical bundle bytes now have distinct
> submission-occurrence nodes, preserving their content commitments. Two negative
> regression cases pass; the full corrected-release suite passes 633 tests.
> The 15-property matrix binds assumptions, real function lines/hashes, verifiers
> and evidence. Historical releases and their signed graphs remain preserved.
> See [the final review](../results/revision-final-formal-correspondence-v2/README.md)
> and [current profiles](FORMAL_PROFILE_CORRESPONDENCE.md).

> Retrospective group validation, 2026-11-03: frozen V2 and an explicitly
> separate envelope-prefix anomaly set are tested on changed identities and
> separately calibrated IID/non-IID cohorts. V2 priority groups miss one attacker
> in all six cases; wider pools retain benign false members. The secondary sets
> recover all three experimental identities but do not prove collusion.
> Main and hard-case follow-up studies add 293 direct removals, 72 continuation
> branches and four full rewinds: 5,670 local calls and 432 genuinely trained rounds.
> Same-start unmodified-tail equality does not reconstruct the inherited W9;
> the post-hoc W0 hard-case replay supports bounded reference reconstruction.
> All 31 relevant tests pass; production algorithms and thesis sources are unchanged.
> See [full outcomes and remaining limits](../results/revision-retrospective-groups-validation-v1/README.md).

> Baseline/DBA validation closure, 2026-11-03: all 1,080 original aggregate
> exports and 144 fixed test endpoints are reproduced; costs now distinguish
> cached aggregation from complete scoring. A secondary 180-context check uses
> separate historical clean references and retains old-composite clean exclusions
> (15/675 IID, 16/675 non-IID). Complete-trigger residual ASR and the interrupted
> literal FedGradTrace Eq. (2) execution remain explicit negative outcomes.
> Source code is unchanged; no new training, TPM or ToN-IoT campaign, or thesis edit.
> See [validated comparisons, costs and limits](../results/revision-baseline-validation-v1/README.md).

> Formal correspondence update, 2026-11-03: definitions and conditional manual
> proofs are consolidated in [FORMAL_MODEL_THEOREMS.md](FORMAL_MODEL_THEOREMS.md).
> This review checks the accepted formal-model obligations; it does not close
> ToN-IoT, group false-alarm validation, baseline cost measurement or thesis writing.

> Update 2026-11-03: the attacked multiround case now includes 20 live rounds,
> 300 fresh emulated-TPM Quotes, 296 independently replayed local trainings,
> explicit-set radii, and actual investigative products. See
> [ATTESTED_DBA_REPLAY.md](ATTESTED_DBA_REPLAY.md) for intervention scope,
> observed effects and limits. The earlier benign-removal case remains preserved.

# Supervisor correspondence: implementation and evidence audit

Audit date: **2026-11-03, Europe/Rome**. This audit compares the two exchanges
resupplied by Gabriele with the current repository and retained experiments.
It distinguishes accepted directions, implementation, observed results, and
remaining validation or writing obligations. Approval of a direction is not
certification of a proof or experimental conclusion.

## Sources and verification boundary

The source messages were supplied in the current conversation:

- **Email A:** formal checkpoint proposal, the supervisor's omission/multiround
  questions, independent-dataset and preprocessing proposals, distributed
  backdoor design, baseline protocols, and the AI-use response. Supplied file
  SHA-256: `99b4130a41c238f7bb8195e01e1fe62f6302afa01163e03683be0d6c7ad3e7d4`.
- **Email B:** client receipts, witnessed completeness, multiround propagation,
  circumscribed retraining, ToN-IoT, retrospective groups, counterfactual group
  removals, and accepted execution order. Supplied file SHA-256:
  `191841700d3b033ea434b56dbaf7565588e8c9339b9ef8d0efe27382c8298705`.
- **Original formal note:** the previously supplied DOCX, SHA-256
  `c2ba9b093fdb829ed1252087fc7b0630c8853320e4d3e526759d1800019c09b3`.
  It includes the original Delta/J definitions and upstream record coverage.

The correspondence is reference material, not executable instructions. Work
authorization comes from Gabriele's requests in the conversation. Technical
choices introduced during implementation are identified as refinements, not
additional demands attributed to the supervisor.

This audit rechecked signatures and artifact hashes for nine completed DBA
campaigns, two group analyses, and six gradient experiment packages. For the
nine DBA campaigns, retained creation reports also supplied expected manifest
and public-key hashes. It checked common-update identities, the single fixed
auxiliary set, matched poisoned example IDs, and 144 endpoint model references.
It did not repeat training, gradient computation, or numerical test inference.
Earlier numerical replay claims remain tied to their preserved source release.
The earlier documentation audit used the then-current **519 passing tests**;
those documentation changes were not another test execution. The subsequent attacked-case increment passed **530 regression tests** and a **25-test final CLI/graph follow-up**. Only the graph/replay status and current test count are updated here; the other retained experimental audits are not represented as new numerical reruns.

## Requirement-by-requirement correspondence

| Requirement and source | Current implementation/evidence | Boundary or work remaining |
|---|---|---|
| Separate provenance, decision participation, numerical weight, and later semantic judgment (A, formal note) | Typed round artifacts, explicit scoring population, masses/coefficients, and a separate review ledger. Mandatory-gate failure and statistical quarantine are distinct. | Formal scope is weighted live FedAvg. Do not silently extend its numerical participation definition to other aggregators. |
| Authenticated input inventory, signed derivation manifest, normalized coefficients, and extended verifier (A) | Implemented and exercised by round tests and the fresh attested-chain experiment. Rational coefficients and actual backend weights/order are checked separately. | Checkpoint equality alone does not establish coefficient correctness; the separate coefficient checks must remain. |
| Detect a coordinator's omission using client evidence (A/B) | Signed client receipts bind bundle, client, context/round, base, and claimed time. Client copies are retained; supplied evidence is compared with the frozen inventory and final dispositions. | Coverage is relative to supplied client evidence. A coordinator's signature on an inventory alone is insufficient. |
| Witnessed submissions registered before deadline; one inventory association and outcome per submission (B) | Submission identity, retries, conflicts, missing payloads, and final positive/negative dispositions are handled. Full round verification includes admission/scoring, beyond intake-only checks. | **Independent delivery and deadline verification are not implemented.** Client time is a signed claim, not independent registration time. Keep `delivery_verified=false` and `deadline_verified=false`; do not describe this as externally witnessed timely registration. |
| Stronger independent append-only witness (B) | The current threat model and documentation discuss the stronger alternative and explain why local copies are not administratively independent witnesses. | A production witness is not present. The supervisor explicitly accepted discussing stronger alternatives without requiring all of them to be implemented; this limitation must be stated in the thesis. |
| Append-only semantic reviews, historical immutability (A, formal note) | Authorized reviewer roster, signed global/subject chains, expected-head append, retry identity, and read-only verification. Historical decisions and models are not rewritten. | Rollback/fork rejection requires a trusted retained head. Evidence payloads and claimed review times are not independently authenticated merely by signing their references. |
| Multiround provenance through checkpoints, predictions, explanations, and reports (A/B) | Authenticated campaign graph and typed blast-radius queries; the attested campaign includes actual M7 products rather than only fixtures. | Reachability is relative to the supplied manifest view. It does not prove that every product ever created was registered or that structural dependency caused measurable damage. |
| Direct counterfactual and at least one circumscribed replay from the corrected checkpoint (B) | Frozen-decision/rescore modes, the preserved benign case, and a new attacked case with 20 live rounds, 300 fresh emulated-TPM Quotes, 296 separately replayed local trainings and actual M7 products. Explicit one-submission and three-submission interventions are bound to their source contexts. See [ATTESTED_DBA_REPLAY.md](ATTESTED_DBA_REPLAY.md). | The new case uses declared feature-space poisoning and supplied experimental ground truth. Five rounds are a bounded implementation choice. It does not establish automatic attacker discovery, certified unlearning, physical TPM protection, global product completeness, or independent delivery/deadline verification. |
| Original indirect-influence measures (formal note) | `proposal_metrics` restores full-population Delta and binary J. Survivor diagnostics remain separate. | `not_submitted` explicitly fills absent/removed slots. J can be one solely because a slot was removed; it is not sufficient evidence of changed survivor decisions. Undefined normalization stays undefined. |
| Coverage of ingested records, including many-to-one transformations (formal note) | Signed pre-replay inventory and outcome manifest for JSONL and Data24 CSV/Parquet; every occurrence receives a derivation or motivated exclusion. Full replay verified 1,916,757 real Data24 records. | This commits input before the new replay, not retroactively before the historical transformation. Capture truth/completeness and independent chronology remain outside the claim. Future converters need their own explicit profile. |
| Diagnose transfer failure; test log transforms, train-only winsorization, count/proportion treatment, and ablations (A) | Data22 diagnosis, seven central representations across three seeds, and six federated confirmation runs. Training-derived transforms and validation selection are recorded. | Data22 had already been observed. Later alternatives are exploratory; they are not a fresh independent external test or proof of a unique failure cause. |
| Independent ToN-IoT compatibility check and documented differences (A/B) | `revision_ton_iot_preflight.py` and tests check declared columns, values, units, labels, and release-scope concerns. | No completed real-data compatibility report or 25-feature coverage/difference matrix was located in the inspected results. A sampled Train_Test CSV does not itself establish equivalent window counts/fractions. |
| Frozen Data24 model/scaler/rules transfer, then same-pipeline ToN-IoT retraining; binary/explicit shared labels (B) | The preflight records these required steps and avoids silent imputation or forced MITRE mapping. | **Not executed in the retained results inspected.** These experiments remain conditional on actual feature/window compatibility. Data22 does not replace this separate ToN-IoT obligation. |
| Genuine distributed local poisoning, full/sub-trigger evaluation, matched budget, and persistence (A) | Nine completed trajectories: clean/distributed/complete-trigger × three seeds, 15 rounds each. Attack rounds 1–10; clean continuation 11–15. Components are assigned to distinct clients; actual local training consumes poisoned rows. | The attack is explicitly in feature space; physical realizability in primary network logs is not established. Poisoned example IDs match between distributed and complete attacks, but the number of edited feature values differs. |
| Retrospective groups from centered updates, temporal indicators, and per-tensor profiles; clean-only calibration (A/B) | Two signed analyses on seed 341593 at rounds 10 and 15 use all three signals. Candidate selection is saved before consulting attacker identities; calibration uses one clean campaign. | Both analyses returned **no candidate groups**. This is a negative detector outcome. The 105 clean pair observations are not independent campaigns, and held-out clean false-alarm validation after group search remains open. |
| Individual versus joint removal; distinguish compatible coordination from proof of collusion (B) | Each analysis evaluates 24 unique removals, including the known three-attacker group, its individual members, and 20 benign size-matched controls. | Because no candidate group was detected, these are explicitly **oracle-labelled diagnostics**, not successful automatic discovery. At round 10, joint FedAvg ASR reduction is 0.4739203589; its excess over the largest individual reduction is 0.0308468873. At round 15 the joint reduction is zero. No causal-intent or significance claim follows. |
| FLAME/WeiDetect initially on identical updates, preserving method components and fixed auxiliary data (A) | **Already executed:** each has 135 common-input round comparisons across the nine trajectories. Every comparison used the same recorded client order and update hashes; one fixed auxiliary-set file hash was used across campaigns. FLAME records clustering, clipping, and nonzero noise; WeiDetect consumes auxiliary F1 scores. | These are conditional comparisons along FedAvg trajectories, as accepted in the mail, not separate live-defense trajectories. Consolidate detection/false-positive/benign-exclusion metrics and measured computational costs; source adapter assumptions remain explicit. |
| Separate live FedGradTrace instrumentation (A) | Actual gradients are collected in six clean/distributed experiments with gradient-FedAvg and explicit Eq.2/Eq.3 interpretations. Five trajectories completed ten rounds; distributed Eq.2 stopped after three completed rounds with a reproduced nonfinite-value failure. | Do not count the failed prefix as a completed trajectory. This is an explicitly scoped adapter/diagnostic, not a full FedXLog reproduction. Its 10% poisoning budget differs from the final DBA benchmark's 50%; avoid cross-protocol superiority claims until settings and method interpretation are reconciled. Fresh TPM attestation was not performed in these gradient runs. |
| Clean accuracy, full/sub-trigger ASR, detection, false positives, benign exclusions, and computational cost (A) | Frozen endpoint test results exist for rounds 10 and 15, covering nine campaigns and eight methods: 144 source-model references checked here. Clean and triggered outcomes and selection/admission metadata are retained. | The fixed-endpoint test report was written after the individual training manifests closed; those manifests do not bind that later report. Final closure/reproducibility and cross-method detection summaries still need consolidation. Defense timing was not found in the inspected runner/reports and must not be invented. |
| Explicit hypotheses, conditions, conclusions, and logical process (B) | Formal review, protocol files, negative results, software/TPM distinctions, and the evidence boundaries above provide the necessary material. | The final thesis must carry these conditions beside its claims, rather than relying on this audit alone. |
| AI-use explanation and prose review (A) | The historical response was acknowledged by the supervisor. | Reconcile the final declaration with subsequent assistance in code, tests, formalization, experiment execution, and analysis. Do not automatically reuse an earlier description of the work as the account of later contributions. No independent authorship certification is implied by the exchange. |
| Accepted execution order (B) | Formal model, receipts, graph, and replay have been implemented first; DBA/group/baseline experiments also exist. | ToN-IoT remains a separate unfinished track. Acceptance of the initial milestone did not cancel the remaining experiments. |

## Corrections to earlier status summaries

Earlier summaries that described FLAME/WeiDetect as code without executed
common-update comparisons were incomplete. The retained campaigns contain
135 comparisons for each method and fixed-endpoint test results. The remaining
work is consolidation, missing metrics/costs, interpretation, and final evidence
closure—not implementation of the entire comparison from scratch.

Earlier summaries also understated the group analysis. Both analyses, their
clean-only calibration, individual/group interventions, and size-matched controls
exist and pass the integrity checks performed here. Their detector result is
negative, and their single-campaign calibration is limited. A successful
oracle-labelled removal is not a detected group.

The distributed Eq.2 package is a preserved, reproducible failure prefix, not
an absent experiment and not a completed ten-round trajectory. Five other
gradient trajectories completed; their status must not be conflated with it.

The 519-test result and completed formal-core work do not close every accepted
email requirement. In particular, they do not establish ToN-IoT compatibility,
independent submission registration time, held-out group false-alarm behavior,
or computational-cost measurements for all baseline defenses.

## Evidence locations

Paths below are relative to the original repository. Large experiment folders
are local retained evidence, not necessarily Git-tracked publication material.

- Formal implementation review: [FORMAL_MODEL_REVIEW.md](FORMAL_MODEL_REVIEW.md).
- Receipts and round profile: [SUBMISSION_EVIDENCE.md](SUBMISSION_EVIDENCE.md)
  and [ROUND_DERIVATION.md](ROUND_DERIVATION.md).
- Multiround/replay: [MULTIROUND_DERIVATION.md](MULTIROUND_DERIVATION.md),
  [COUNTERFACTUAL_REPLAY.md](COUNTERFACTUAL_REPLAY.md), and
  [ATTESTED_LIVE_CHAIN.md](ATTESTED_LIVE_CHAIN.md).
- New record coverage: [INGESTION_COVERAGE.md](INGESTION_COVERAGE.md);
  `artifacts/revision-formal-alignment-v2/data24-record-coverage/`.
- Attested replay: `artifacts/revision-attested-chain-v4/`.
- Data22: `artifacts/revision-preprocessing-screening-v1/` and
  `artifacts/revision-preprocessing-federated-v1/`.
- DBA/baselines: `artifacts/revision-dba-three-seed-v1/`, including the
  predeclared protocol, nine creation/verification reports, per-round
  `comparison.json`, and `fixed-endpoint-test.json`.
- Groups: `artifacts/revision-dba-groups-v1/` and
  `artifacts/revision-dba-groups-attack-end-v1/`; both refer to the clean and
  distributed seed-341593 trajectories in the three-seed benchmark.
- Gradient diagnostics: `artifacts/revision-fedgradtrace-live-v1/`.
- Audit integrity checks and translated-document backups are retained in the
  local audit workspace under `output/email-audit-20261102/`. That folder was opened
  before the local date changed; the audit date is 2026-11-03 as stated above.

## Next closure obligations

1. Perform and retain the real ToN-IoT field/units/window-coverage audit. Run the
   frozen-model and retrained-pipeline protocols only if compatibility holds.
2. Consolidate the already executed DBA/common-update experiments, including
   detector/exclusion metrics, measured defense costs, and final test evidence
   closure. Preserve negative outcomes and the feature-space limitation.
3. Evaluate group false alarms on clean campaigns not used for calibration;
   keep candidate detection separate from oracle intervention diagnostics.
4. Resolve or explicitly report FedGradTrace's equation/instability and protocol
   differences before making a comparable baseline claim.
5. Update the thesis from verified results and the reviewed formal statements,
   including the actual scope of AI assistance. The existing thesis draft is
   not yet synchronized with the latest formal/attested increments. No thesis
   edits or new numerical experiments were performed in this documentation audit.


## Follow-up: separated influence and successful-attack replay (2026-11-03)

The original fixed-population Delta/J definitions are retained. New versioned
diagnostics distinguish removed weight, survivor action changes, policy total
variation against removal-only renormalization, and direct/additional/total model
distances. Their L2 scalar values are not additive. Historical observed eligibility,
effective gate and scoring membership are exposed separately.

The composed investigation API verifies every supplied graph round with the full
admission verifier before setting its top-level policy-revalidation flag; anchored
reviews and exact intervention/source binding are checked separately. Deadline and
global artifact completeness claims are not strengthened by this composition.

All three historical DBA seeds now have full retraining interventions from before
the attack, with a byte-identical replay control and a clean matched-participation
branch. Both single and group removal yield ASR zero at attack end; this does not
demonstrate extra group synergy, and the single-removal models still differ from
the matched clean models. The original control also recovers ASR zero after clean
training. These software experiments remain distinct from fresh TPM evidence.

See [definitions, results and verification scope](../results/revision-effective-influence-v1/README.md).


## Clean reconstruction and group-analysis follow-up (2026-11-03)

An exact-history comparison API now separates ASR zero from matched clean-reference
equivalence. Ninety reconstructed checkpoints match the intended clean references;
the previous partial removal remains non-equivalent. A pair-conditioned group
pilot uses disjoint clean fitting/calibration and new evaluation training seeds.
Its candidate pool still has false clients and missed membership and is not
validated for automatic exclusion.

A separately qualified same-base execution audit, requiring original unmodified
client snapshots, identifies every experimental execution deviation in the six
evaluation campaigns. Its selected full-history removals match clean references
exactly. This privileged result is not generalized to update-only FL. The full
suite passes 561 tests; the step includes 5,010 local training calls and 300 new
aggregation rounds, all software/analyst evidence. Existing attested evidence and
the thesis remain preserved.

See [profiles, results and remaining scope](../results/revision-clean-reconstruction-and-groups-v1/README.md).


## Incoming-state consistency follow-up (2026-11-03)

The new observable-only audit separates a local update departure from a benign
response to an already affected global checkpoint. It remains statistical evidence,
not semantic truth or a gate override. Frozen evaluation covers changed attacker
identities in IID and non-IID data; ordinary and matched-state clean controls;
all predeclared predictor views; direct effects and complete selected-history
retraining. Primary fusion misses one high-weight non-IID client and has false
candidates, so it is not promoted to automatic exclusion. Exact clean-reference
history equality does not establish that every excluded client was malicious.

See [the frozen study](../results/revision-state-conditioned-audit-v1/README.md) for
all counts, the file-access boundary, calibrations, trade-offs and unresolved scope.


## Prefix-only, round-scoped policy follow-up (2026-11-03)

The experimental `sequential_decision` module separates review from temporary
quarantine. Both score views remain visible. Cumulative evidence uses a fixed
clean-calibrated recurrence and strict round/predecessor bindings. For fixed
calibration and an identical observation/gate/mass prefix, induction on the
deterministic recurrence gives identical prefix decisions regardless of future
inputs. This is a causal-input property, not a theorem about classification
accuracy. The two views are correlated and do not provide independent votes.

Mandatory rejection always gives zero effective mass. Statistical evidence cannot
override it. A changed eligible population invalidates the fixed-cohort detector
and causes review/abstention. Quorum failure never re-admits excluded updates.
Current-round quarantine is neither a permanent ban nor a semantic malice label.
Hash chaining assumes a trusted expected predecessor; the local analyst closure
is not an independent witness, a trusted timestamp or a fresh TPM attestation.
The experimental worker is not wired into live admission and does not validate
invalid-payload handling by the production path.

The 24 reserved episodes, action costs, latency, coverage, ASR trajectories and
clean utility are reported in [the frozen online study](../results/revision-sequential-round-policy-v1/README.md).
It does not replace the approved retrospective candidate-group scope or historical
replay. No automatic repair of previously affected checkpoints is claimed.


## Current-evidence confirmation and statistical release (2026-11-03)

The added `current_evidence_policy` module keeps the previous evidence engine
unchanged and separates its cumulative review evidence from quarantine authority.
For supported gate-compatible current high evidence H, the action is
Q(i,t) = H(i,t) AND H(i,t-1). Hence quarantine is a subset of current high
candidates; a stale cumulative score cannot authorize or prolong it. Failure of
current high evidence releases statistical quarantine immediately. Release does
not override mandatory rejection, prove benign intent or erase prior provenance.
New entry after a gap requires new confirmation. Fixed-calibration deterministic
prefix invariance, strict round order, trusted predecessor and exact-observation
bindings are preserved. Classification accuracy is an empirical question.

The new fixed-protocol study includes changed attackers, short attacks, cessation
and a clean gap between bursts, with shadow proposals counted as well as actual
active actions. The thresholds remain unchanged. All 604 tests pass. This remains
an experimental adapter: no fresh TPM attestation, live admission integration,
permanent ban or automatic repair of earlier checkpoints is claimed. See
[the complete reserved evaluation](../results/revision-current-evidence-policy-v1/README.md).


## Individual clean envelope and evidence retreat (2026-11-03)

The added empirical policy separates client-specific departures from a global
worst-client cutoff. Its additional channel uses positive current minimum excess
over a fixed per-client/view clean envelope, a peak within the uninterrupted
positive episode, and two consecutive observations retaining at least half that
peak. The peak can suppress an action; it cannot authorize one without current
evidence. The final union requires either a confirmed prior current channel or
the confirmed additional channel. Neither a stored peak nor cumulative review
score alone can quarantine an update. Gate rejection remains non-compensable,
unsupported contexts break confirmation, and failed quorum cannot restore
excluded mass. Statistical release is not a semantic benign label.

Geometry-only filtering was rejected empirically rather than silently promoted.
Method selection uses only declared historical development observations. The
new frozen persistent-attack comparison trains all three active/control
histories and counts shadow proposals as well as actual exclusions. All 631
tests pass. Finite empirical accuracy, population false-positive guarantees,
semantic malice and historical clean-state recovery remain separate claims.
No new TPM attestation, live deployment or permanent ban is introduced. See
[the full prospective results](../results/revision-individual-envelope-v1/README.md).


## Baseline/DBA evidence and measured cost (2026-11-03)

Step 1 consolidates the retained common-update comparisons, independently
replays 1,080 aggregate model exports and 144 test endpoints, and reports
full/component ASR, clean accuracy, macro-F1, operational exclusions,
downweights and measured wall/CPU/process-memory scopes. Cached WeiDetect F1
and composite masses are not counted as complete scoring. Current envelope
inference/policy/aggregation cost is measured in a separate stateful scope.

The original old-composite clean exclusion result was in-sample. A secondary
180-context IID/non-IID check using fixed separate historical clean references
exposes 15/675 and 16/675 clean exclusions, respectively. Its 900 conditional
outputs and 120 fixed test evaluations preserve inherited-state contamination
and all component outcomes. Unequal clean-reference information requirements
prevent a universal equal-information superiority claim.

FedGradTrace remains a qualified MLP adaptation of two distinct printed
recurrences, not a full FedXLog replication or a malicious-client classifier.
All 53 completed native-gradient exports replay exactly. The unstable Eq. (2)
fourth round and protocol differences are preserved; zero ASR in the attacked
gradient FedAvg control prevents attributing Eq. (3)'s zero ASR to mitigation.

This closes consolidation/measurement for the declared protocols; it does not
claim that every attack was remediated or every baseline reproduced end to end.
Selected-group individual/joint removal and benign controls are next, followed
by final formal correspondence, adaptive/live-TPM policy work and thesis writing.
ToN-IoT remains explicitly deferred. No production code or thesis source changed.


## Retrospective selected sets and causal tails (2026-11-03)

The requested individual/joint/benign comparisons are extended to changed
attacker identities and separately referenced IID/non-IID cohorts. This is a
secondary analysis of existing histories. Selection closes on rounds 1–10
before truth or ASR is used; full V2 candidate pools and selection mistakes
remain visible. The envelope-prefix collection is separately labelled as an
anomaly-selected set, not a pairwise collusion classifier.

Direct R10 reaggregations are followed by genuine R11–15 local retraining from
each corrected branch checkpoint. Remaining scripted poisoning is retained.
Benign controls match set size and additionally include closest original sample
mass; their ranks are descriptive rather than p-values. The no-intervention
tails reproduce 450 local outputs and 30 newly trained checkpoints exactly.

For each selected set, same-W9 unmodified-data reference tails check the complete
future execution. That reference can inherit an already poisoned checkpoint;
its equality does not establish a globally clean pre-intervention history.
All-client clean-history differences also reflect changed participation.
The report preserves residual ASR, false pool members, missed membership,
individual effects, benign controls and complete/component test outcomes.

After observing the largest late-removal residual, a separate recorded post-hoc
follow-up replays that same frozen selected set from W0 through all 15 rounds.
It does not retune discovery. Four full histories add 810 local calls and 60
trained rounds: original source reproduction, selected-set exclusion, matched
unmodified reference and all-client unmodified reconstruction. All source/clean
reference payloads match, while complete selected-history equality concerns
the reduced population. The all-client reconstruction requires the original
unmodified snapshots and declared starting-state/environment assumptions.

This strengthens the accepted retrospective claim of compatibility with
coordinated behaviour. It does not prove malicious intent, complete update-only
collusion identification or automatic live exclusion. No new TPM or ToN-IoT
campaign and no thesis edit is introduced. Final formal correspondence,
adaptive/live policy qualification and thesis integration remain separate steps.


## Final conditional-proof/code/evidence correspondence (2026-11-03)

The original proposal and both supplied exchanges are pinned read-only sources.
The final matrix covers the accepted core and distinguishes newer empirical
adapters. The review corrected content-based aliasing of distinct submissions:
cross-round rejected replay could create a cycle, and same-round borrowed bytes
could inherit another client's numerical/scoring descendants. Node identity now
uses submission ID; the node's content SHA remains the bundle byte hash.

The corrected release passes 633 tests and the current finite obligations.
The earlier 631-pass run and old-source counterexamples remain preserved. The
historical 104-file release independently rechecks its 4,135 typed witnesses;
the old attested graph has 296 distinct origins for 296 submissions and does not
contain the newly identified alias condition. Its 20 live round instances are
four five-round branches, not one 20-step trajectory. No new TPM or training
campaign is added by this review.

Receipt coverage still depends on supplied retained client evidence, record
coverage on named committed source profiles, and review rollback detection on
externally retained heads. The newer empirical adapters emit proposed masses:
unsupported abstention can retain eligible mass and quorum, so it is not the
original full live-admission/scoring theorem. Exact history comparison requires
caller authentication and seed/optimizer-contract checks. Statistical success,
semantic truth, independent deadline/delivery, all-product completeness and a
physical TPM are not inferred.

The thesis handoff carries these bounds, model-index translation, all empirical
negative outcomes and the need for an accurate assistance disclosure. Adaptive
and live-TPM policy validation remain separate; ToN-IoT stays deferred. The
actual thesis and Git index are unchanged.


## Bounded live-envelope validation — 3 November 2026

The separate observable-envelope live profile now has a fresh swtpm integration case, an authenticated unsupported-context failure and five rejected tamper cases. The current full suite passes 652 tests. The real adaptive pilot demonstrates peak suppression; bounded-persistence candidates failed their development guardrail and were not promoted. The five-round live control has zero ASR even without statistical quarantine, so no live ASR mitigation advantage follows. This is a new versioned empirical profile; prior formal/source closures remain preserved. The thesis and ToN-IoT remain unchanged. Details and exact evidence: [LIVE_ENVELOPE_VALIDATION.md](LIVE_ENVELOPE_VALIDATION.md).


## Rolling-peak follow-up — 3 November 2026

The frozen two-round candidate passed old development guardrails but failed the real adaptive replication. It is not promoted; the maintained live package is unchanged. See [ROLLING_ENVELOPE_VALIDATION.md](ROLLING_ENVELOPE_VALIDATION.md).


## Bounded influence profile — 4 November 2026

An explicit experimental per-tensor containment profile now preserves authenticated originals and derived deltas separately, with final-source tests, a conditional influence proof and a fresh swtpm mechanism case. Full-trigger ASR is reduced in the specified offline adaptive replication; component-trigger residuals and model-state differences remain. This does not validate semantic client exclusion or universal decontamination. The original raw-update counterfactual profile remains versioned; the bounded profile uses its explicit clipped-delta operation. Details: [BOUNDED_INFLUENCE_VALIDATION.md](BOUNDED_INFLUENCE_VALIDATION.md).
