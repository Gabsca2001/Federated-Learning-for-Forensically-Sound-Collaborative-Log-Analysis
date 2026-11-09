# Rolling peak memory: validation and rejection

The two-round rolling-peak candidate is **not promoted**. It resolves the old
single-peak/constant-weak-excess example, but an attacker that knows the new head
can alternate stronger manipulation and unmodified updates and evade the
two-observation confirmation mechanism. This is an empirical counterexample,
not a statement that no other detector could work.

## Frozen development

The unchanged clean-only predictors and envelopes are reused. Windows 2, 3 and
4 were declared before scoring the 48 already-used development cases. Selection
required zero never-attacker and currently-clean scheduled-attacker exclusions
and no quorum loss, then maximum shadow interceptions and smallest window.
Window 2 scored 474 intercepted poisoned updates versus 452 for the old head,
with zero observed false proposals. This was development, not a held-out result.
No thresholds were refitted on attack identities or outcomes.

## New paired active trajectories

The candidate was frozen before eight fifteen-round trajectories: IID seed
561593, non-IID seed 571593, clean/DBA training, old/rolling active heads.
Attackers are client02/09/14 and client03/08/12 respectively. Attacks occur at
rounds 1–6; rounds 7–15 use unmodified training from the actual evolving model.
This tests delayed exclusion of clean responses to contaminated bases. There is
one new seed per cohort, on the same dataset, with no independent-dataset claim.
Both heads generate their own successors, not frozen-update approximations.

| Cohort | Training | Head | Completed rounds | Intercepted poisoned updates | Currently clean exclusions | Peak full-trigger validation ASR |
|---|---|---|---:|---:|---:|---:|
| iid | clean | retreat | 15 | 0 | 0 | 0.0000% |
| iid | clean | rolling-2 | 15 | 0 | 0 | 0.0000% |
| iid | distributed | retreat | 15 | 15 | 0 | 0.0000% |
| iid | distributed | rolling-2 | 15 | 15 | 0 | 0.0000% |
| non-iid | clean | retreat | 15 | 0 | 0 | 0.0000% |
| non-iid | clean | rolling-2 | 15 | 0 | 0 | 0.0000% |
| non-iid | distributed | retreat | 15 | 11 | 0 | 0.0000% |
| non-iid | distributed | rolling-2 | 15 | 15 | 0 | 0.0000% |

Counters: {"generation_local_trainings": 1800, "repeated_local_trainings": 240, "rounds_verified": 120}. Local training at rounds
1 and 15 of each completed trajectory is repeated exactly. Every retained
decision and aggregate is replayed. This deterministic verification is not a
mathematical proof of semantic correctness or an independent implementation.
All fixed endpoints include clean utility and complete/component triggers;
the test split is not accessed. Quarantine counts refer to current manipulated
updates; unmodified updates can still inherit effects through their shared base.

## White-box adaptive replication

The previously known non-IID seed 551593 case is deliberately replicated against
the new frozen head. It is not presented as a new held-out seed. The adversary
has the same ten-candidate query budget per round and uses validation ASR.
Every round trains unmodified and poisoned local endpoints from the actual
current base and modifies only its three exports. Its chosen factors are
`[2.0, 0.75, 0.75, 0.0, 2.0, 0.75]`. A factor of zero is an actually unmodified export for that round,
not a poisoned update. The trajectory contains 15 nonzero manipulated
updates and 0 total quarantines.

Peak full-trigger validation ASR is **26.8087%**, final ASR
**3.5895%**. The matched six-round
clean arm has zero full-trigger ASR. All **270 local trainings, 60 candidate
queries and 12 aggregates** are repeated exactly. This is a bounded offline
post-training manipulation experiment, not a TPM or declared-training-contract
bypass. The chosen factors depend on the head and change its future bases;
comparison with the older pilot is not a paired fixed-update superiority test.

## Conditional mathematics and remaining limit

For window H, an isolated old peak leaves the window after H observations.
If supported positive excess then remains constant, it becomes non-receding
and two current observations confirm it. The blanket promise of a fixed
confirmation bound for every positive sequence is false: alternating excess
0.4/0.01 above a limit can alternate retained/receding observations forever.
The six prototype tests include this counterexample, exact retry binding,
failed gates, unsupported resets, sharp-retreat release and window identity.
The real adaptive experiment demonstrates a related evasion with trained
model updates. A signed submission establishes origin, not semantic innocence.

Changing a peak window or a confirmation counter alone is insufficient for
the intended automatic-exclusion claim. Stronger containment should be evaluated
as a separate aggregation/influence contract, with detector alerts kept distinct
from proof of malice; see [the next-step design](../results/revision-rolling-envelope-validation-v1/NEXT_STEP_DESIGN.md).

## Integrity and scope

The prototype and its six tests are research files under this output directory;
the maintained 117-file live package remains unchanged at
`9756ea7efd479992a9aecfc45953b476131e1ad9edfa0bfae32032db50839ff7`. Its previous 652-test validation and TPM evidence
remain versioned, not relabeled as tests of this prototype. No new Docker/TPM
campaign, ToN-IoT work, commit, push or thesis edit is performed here. All new
reports are in English. Raw evidence is retained in the two versioned artifact
directories, with a source/controller archive and local analyst-signed closure.
The closure is an integrity record, not independent witness time or certification.
