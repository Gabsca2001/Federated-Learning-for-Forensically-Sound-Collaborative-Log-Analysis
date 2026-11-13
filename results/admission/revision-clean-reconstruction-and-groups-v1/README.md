# Clean reconstruction and retrospective group analysis

Date: 2026-11-03. Branch: `revision/derivation-protocol`.
This step changes analyst-side code and experiments; it does not edit the thesis.

## Answer to the structural question

Two localized extensions are necessary: an explicit clean-reference contract for
reconstruction, and a separate, calibrated candidate-selection/evaluation pipeline.
They should not be collapsed into a single claim that ASR zero means a model is
clean or that a graph descendant must be malicious.

The implementation now distinguishes three evidence profiles:

| Profile | Available evidence | Supported result |
|---|---|---|
| Matched clean-reference reconstruction | Declared intervention, clean reference snapshots, starting checkpoint, deterministic training state | Exact equality of the complete reconstructed reference history |
| Update-only group hypotheses | Historical updates and admission indicators, clean reference/calibration campaigns | Empirical candidate selection, false-positive/missed-client measurements and conditional intervention effects |
| Privileged same-base execution audit | All preceding commitments plus original unmodified client snapshots and a reproducible clean training execution | Exact detection of deviations from that reference execution, followed by reconstruction of the matched clean history |

The third profile requires access to original client data. It does not establish
that the second profile works under a parameter-only federated privacy boundary.

## 1. Why the earlier model differed from the clean control

The earlier single-removal branch omitted client01 while client06 and client11
continued poisoning. The clean matched single branch removed the same client but
disabled all poisoning. These trajectories had different remaining training
inputs, so exact model equality was not expected. ASR zero only described the
measured target behavior.

The new acceptance contract compares the entire horizon, not only ASR or the last
checkpoint: ordered participation, starting/global model hashes, committed local
training rows, local model hashes, and checkpoint continuity at every round.

`src/fl_forensics/remediation_validation.py:compare_replay_histories` implements
this exact comparison over normalized commitments. It intentionally reports that
payload authentication must be performed by its caller. The case verifier first
checks the artifact closures, historical signed source manifests, public-key pins,
committed datasets and actual model payload hashes before applying the API.

Under equal initial model, ordered participation, clean local data, per-client
seeds, optimizer reset policy, training code/environment and aggregation order,
deterministic local training yields equal local outputs in round 1; aggregation
therefore yields equal next checkpoints. Induction gives equality at every later
round. This is conditional reference equivalence. A dataset commitment alone does
not prove that its contents or the warm checkpoint were semantically clean.

Two fresh reconstructions per seed were executed for all three original seeds
(341593, 342593, 343593):

- **Clean matched group:** omit client01/06/11 in rounds 1–10, return them clean in
  rounds 11–15. Every output matches the earlier whole-group removal history.
- **Repair all experimental poisoning:** keep all 15 clients, use their original
  unmodified snapshots. Every output matches the original all-participant clean
  campaign.

All **90 checkpoints and 1,260 local outputs** match their declared references
byte-for-byte. The earlier partial single-removal histories correctly fail the
same comparison despite ASR zero. Historical evidence was not rewritten.

## 2. Concrete defect in the previous group calibration

The v1 calibration clips raw similarity thresholds at 1 while the detector requires
a strict exceedance. For tensor-profile correlation this produced a threshold of
exactly 1, making that channel impossible to exceed. The rule also required at
least two exceeded feature thresholds. The true distributed attackers often
exceeded only the temporal channel, while some benign pairs were persistently
similar because of their fixed local data.

A development diagnosis fitted each fold on two clean seed trajectories and
evaluated the third clean trajectory plus its attacked counterpart. This is a
diagnostic on previously used data, not an untouched validation. It found missed
attackers and benign candidates. The original v1 implementation remains available
to reproduce its historical profile; it should not be presented as validated
automatic collusion identification.

## 3. Structural update to candidate generation

`src/fl_forensics/group_calibration_v2.py` introduces:

1. A robust clean baseline for each registered client pair and feature, accounting
   for persistent benign pair similarity. Scales use `max(0.05, 1.4826*MAD)`.
2. A score equal to the largest positive standardized increase over that pair's
   baseline. No channel requires a raw correlation greater than 1.
3. A threshold fixed from the maximum over every pair/channel in each separate
   clean calibration campaign, followed by a strict score exceedance.
4. Maximal cliques of qualifying edges, preventing a chain of pair similarities
   from automatically becoming one mutually connected group.
5. Explicit rejection of reused campaign fingerprints between fitting,
   calibration and evaluation, or a changed client population/reference.

V2 is an experimental method designed after inspecting the original development
seeds. Its parameters were frozen before generating the new training runs.
The split was:

- Fit: original clean seeds 341593, 342593, 343593.
- Threshold calibration: new clean seeds 351593, 352593, 353593.
- Evaluation: clean/attacked pairs for new seeds 361593, 362593, 363593.

The nine new campaigns comprise 90 rounds and 1,350 local training calls. Only
observable deltas/indicators enter detection. Candidate files close before attack
identities or ASR enter evaluation. The fixed calibration threshold is
7.50787641599356. No threshold was changed after seeing the new outcomes.

These seeds vary training randomness; client datasets and experimental attacker
identities remain fixed. This is not held-out attacker identity, new-dataset or
non-IID validation. Three clean calibration/evaluation campaigns cannot establish
a small general false-alarm probability. Client pairs within a campaign are
dependent, so 105 pairs are not 105 independent trials.

## 4. Update-only results: useful but incomplete

There were no candidate groups in the three clean evaluation campaigns. On the
attacked campaigns, the complete candidate pool has these client-level results:

| Seed | True clients flagged | Benign clients flagged | Missed attackers | Pool precision | Pool recall |
|---|---:|---:|---:|---:|---:|
| 361593 | 2 | 0 | 1 | 1.0000 | 0.6667 |
| 362593 | 3 | 5 | 0 | 0.3750 | 1.0000 |
| 363593 | 2 | 5 | 1 | 0.2857 | 0.6667 |

No exact three-client maximal clique was recovered. Absence of alarms in three
fully clean campaigns must not hide benign clients flagged during attacked
campaigns.

For a secondary intervention study, candidate cliques were ranked by their weakest
conditioned edge, with a lexicographic tie break. That rule was recorded before
the interventions; it is a secondary assessment on the same pilot outputs, not
an additional independent validation set. The top selected group was client01–
client11 in all three attacked campaigns. Client06 was still absent from this
selected group.

| Seed | Original ASR | Direct R10 group-removal ASR | Extra direct reduction beyond best individual | Full-history removal ASR | Equal to matched clean history? |
|---|---:|---:|---:|---:|---|
| 361593 | 46.7751% | 0% | 2.9164 percentage points | 0% | No |
| 362593 | 45.4291% | 0% | 1.0656 percentage points | 0% | No |
| 363593 | 45.8216% | 0% | 2.2995 percentage points | 0% | No |

All 66 benign two-client controls per campaign were also evaluated at round 10.
None was at least as effective as the selected pair. Removing benign pairs instead
increased ASR in these particular conditional comparisons. These 198 controls
provide descriptive effects, not independent p-values or proof of intent.

The direct R10 effect is conditional on stored historical updates. The full-history
study retrained every subsequent update from its branch's actual global model:
60 rounds and 780 new local calls. Its ASR zero still failed exact clean equivalence
because the remaining client06 continued poisoning. This provides a concrete
automatic-selection example of the original limitation, rather than hiding it.

## 5. A stronger forensic profile when original data are available

To distinguish a benign response to a contaminated global model from a local
departure from unmodified training, the new audit replays each local execution
from the **same actual incoming checkpoint**. It uses the original committed
unmodified client snapshot, exact seed, fresh Adam and matching CPU environment.
Its output is a reference-execution deviation, not a verdict on malicious intent.

For all six evaluation campaigns, all 15 clients and all ten rounds, **900 local
reference executions** were performed. Candidate files were closed before
consulting the experimental identity plan. In each attacked campaign, the only
deviating clients were client01, client06 and client11. None deviated in the clean
campaigns. Across the audit there were 90 differing local outputs and 810 exact
matches. In particular, legitimate clients responding to the attacked checkpoint
still match their same-base unmodified reference execution.

The audit-derived set, without substituting the identity plan for selection, was
then used for a second full-history intervention. Omitting that set in rounds
1–10 and independently retraining a matched clean-participation trajectory yielded
exact equality in all three seeds, across every local output and checkpoint:
**60 rounds, 720 local calls**, 360 pairs of equal local outputs and 30 pairs of
equal global checkpoints.

This closes reference-equivalent reconstruction in the privileged profile. It
requires the unmodified snapshots, known training seed/state and reproducible
environment. If only updates are available, the V2 limitations above remain.
If the original committed snapshot is already poisoned, commitment equality alone
does not identify that semantic defect. GPU/nondeterministic executions would
also require a separately justified comparison profile; exact CPU equality is not
silently generalized to them.

## 6. Scientific interpretation and next work

The structural separation required by the supervisor is now operational:

- A graph dependency identifies exposure, including benign downstream responses.
- A group score generates a hypothesis from updates and indicators.
- A same-base execution audit, when its extra evidence is available, checks local
  reference conformity.
- Reaggregation measures a direct conditional effect; full retraining measures a
  declared history intervention.
- Equality to a matched clean history supports reference-equivalent reconstruction.
  ASR zero by itself does not support that conclusion.

Historical-update diversity is also the premise of
[FoolsGold](https://www.usenix.org/conference/raid2020/presentation/fung). That
literature motivates examining observable coordination, but does not validate
this V2 pilot or prove malicious intent from similar updates.

For update-only deployment, further work remains: model benign behavior conditional
on the incoming checkpoint, include singleton/residual anomaly hypotheses, vary
attacker assignments and data distributions, and evaluate more independent clean
and attacked campaigns with frozen decision rules. The measured false candidates
and missed membership prevent promoting the current similarity detector to
automatic exclusion. Attributed semantic review remains separate.

The availability of forensic snapshots is therefore a concrete design choice:
use the stronger audited profile where such evidence is retained and accessible;
otherwise report update-only candidates with measured uncertainty and continue
the independent validation work.

## 7. Validation, evidence and unchanged scope

The complete repository suite passes **561 tests**, zero failures/errors/skips,
two existing Typer deprecation warnings (192.48 seconds). Tests include complete
history/chain/input matching, rejection of ASR-only acceptance, disjoint fitting/
calibration/evaluation, persistent benign similarity and non-clique chains.

This step performed **5,010 new local training calls** in total: 1,260 clean
reconstructions, 1,350 pilot calls, 780 similarity-selected interventions,
900 same-base audit calls and 720 audit-selected interventions. There were 300 new
aggregated rounds. The audit's 60 historical round contexts are not counted again
as new aggregation rounds. Direct reaggregations do not count as client training.

Evidence includes the protocols recorded before each phase, exact-history reports,
full candidate pools and false positives, all controls, source/artifact hashes,
code snapshots and the full test XML. Payloads are retained in the repository
artifact directories named in the integrity manifest. This is software/analyst
evidence; no fresh TPM Quote, independent timestamp or external witness is claimed.
The previous measured releases and signed histories are preserved. The actual
thesis sources and Git index are unchanged in this step.
