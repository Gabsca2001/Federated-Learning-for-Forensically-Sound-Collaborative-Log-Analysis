# Bounded influence: implementation, validation and live integration

The experimental containment profile is implemented and passes its declared
finite checks. It limits each admitted model delta per tensor, retains the
original signed object, and authenticates the separate transformation. It does
not identify malicious intent or establish universal backdoor resistance.

## Versioned implementation

Final package: 119 files, `4b58e1590179dbaa37c8e9760b94bd57549db6c3a228e95f00ee2def26012bbb`.
**678 tests pass**, with two existing Typer warnings. The offline-only package
and first live trial sources are separately retained. The default runtime
configuration is not changed. The new profile is explicitly
`live-client-envelope-bounded-v1`, and checkpoints use
`BoundedDelta-FedAvg-observable-envelope`. The complete authenticated prefix,
frozen assets, original submissions and client receipts are required to verify
it. Missing/unsupported observations keep the existing fail-closed behavior.

`bounded_aggregation.py` creates/reconstructs float64 derived deltas and actual
masses. `live_bounded_aggregation.py` binds the declared limits, materializes
the derived object, and supplies the identical numerical backend for checkpoint
creation and verification. The graph inserts `bounded_update_derivation` between
the original bundle and checkpoint, with explicit base/limit dependencies.
The normalized mass coefficient applies to the derived contribution; raw-input
algebraic coefficients are tensor-specific. See
[the conditional proof](BOUNDED_INFLUENCE_THEOREMS.md) for hypotheses, rounding and
the distinction from causal/semantic claims. Legacy raw-update counterfactual
aggregation explicitly rejects the new profile instead of silently averaging
the originals; clipped-delta removal is a separate operation.

## Frozen clean calibration

Each cohort reuses **3,675 unmodified reference updates**, including responses
to generic perturbed shared states. One common limit per tensor is the fixed
99th percentile, using the `higher` quantile method. Source observable hashes
are checked, and no adversarial-client identities or attack outcomes enter the
fit. These are reused historical clean references on the same dataset, not a
new independent dataset. A clean trajectory means unmodified local training;
its supervised traffic dataset still contains the original network classes.

## Twelve new active trajectories

IID seed 581593 and non-IID seed 591593 each run clean/DBA training under
FedAvg, the original envelope head, and envelope plus containment. All fifteen
rounds use ten attack rounds followed by five unmodified continuations. Each
strategy generates its own future base; this is not frozen-update efficacy.
There is one new seed per cohort. Every fixed validation endpoint is evaluated;
the test split is not used and no clipping threshold is tuned after outcomes.

| Cohort | Training | Strategy | Peak full-trigger ASR | Peak component ASR | Final clean macro-F1 |
|---|---|---|---:|---:|---:|
| iid | clean | fedavg | 0.0000% | 0.0000% | 0.928384 |
| iid | clean | envelope | 0.0000% | 0.0000% | 0.928384 |
| iid | clean | bounded-envelope | 0.0000% | 0.0000% | 0.933642 |
| iid | distributed | fedavg | 62.5911% | 0.0000% | 0.929157 |
| iid | distributed | envelope | 0.0000% | 0.0000% | 0.928384 |
| iid | distributed | bounded-envelope | 0.0000% | 0.0000% | 0.928005 |
| non-iid | clean | fedavg | 0.0000% | 0.0000% | 0.956199 |
| non-iid | clean | envelope | 0.0000% | 0.0000% | 0.956199 |
| non-iid | clean | bounded-envelope | 0.0000% | 0.0000% | 0.955915 |
| non-iid | distributed | fedavg | 14.6383% | 14.2457% | 0.954490 |
| non-iid | distributed | envelope | 0.0000% | 0.0000% | 0.955217 |
| non-iid | distributed | bounded-envelope | 0.0000% | 0.0000% | 0.955781 |

The new trajectories execute **2,700 local trainings**. Another **360 local
trainings** at predeclared first/last rounds match exactly. All 180 decisions and
aggregates are replayed. The 60 bounded rounds additionally yield **854 direct
individual-removal certificates**, including the two checkpoint export-rounding
allowances and 1e-12 numerical comparison allowance.

The maximum paired clean macro-F1 loss is **1.6374 percentage
points IID** and **0.3791 points non-IID**, within the frozen
two-point budget. Clipping an unmodified update is not a malicious-client
classification; utility loss and clipping frequency are reported separately.
In these ordinary cases the original head already attains zero full-trigger
ASR, so the clipping increment has no demonstrated full-trigger ASR advantage
over that head there. The FedAvg controls demonstrate that the attack is
effective in the declared longer ordinary protocol.

## Clipping-aware adaptive replication

The adversary knows the head and clipping limits, trains poisoned and unmodified
endpoints from the actual current base, and evaluates ten fixed candidates per
round against the actual defended aggregate. Seed 551593 is a previously known
case, explicitly a mechanistic replication. Private rows and adversarial-client
identities are used by the controlled generator/evaluator, not the detector.
This offline post-training interpolation/extrapolation does not claim an
undetected TPM training-contract bypass or physically realizable network logs.
The feature-space trigger still uses the declared standardized values.

The first greedy search chose zero manipulation in early ASR ties and remained
ineffective. That result is retained. An explicitly exploratory stronger search
breaks ties in favor of larger allowed manipulation, with unchanged defender
limits. Both defended strategies are rerun under that same stronger objective
and candidate budget. This attack-design follow-up is not held-out certification.

The strengthened unbounded-head control reaches **100.0000% peak
full-trigger ASR**, versus **0.0000%** with containment through
the six fixed rounds. Final unbounded-head ASR is
**97.8688%**.
The bounded model's final clean macro-F1 is **0.938774**;
this result is not explained by a general collapse of clean prediction utility.

There are important residuals: the bounded peak **component-trigger ASR is
1.0656%**, and its final parameter L2 distance from matched
clean is **2.151472401** (unbounded-head distance
3.958382293). Full-trigger ASR zero does not establish complete
removal of poisoning effects, all-trigger security or recovery of clean state.
The bound is on direct numerical influence at a fixed base; later causal
effects still require genuine subsequent training and an explicit comparison.

Across both adaptive search versions, **240 candidate queries and 48 selected
aggregates** are independently replayed from retained original endpoints,
including nonselected candidate ASRs. Each version executes 540 local trainings
and repeats all 540 exactly. Candidate choices are head-dependent, so this is
an active algorithm/attack-budget comparison, not a paired fixed-update test.

## Signed origins and fresh swtpm validation

Before live integration, 75 retained genuine swtpm bundle signatures and
enrollment signatures were checked against their original commitments. Separate
bounded derivations were produced; no original bundle or historical checkpoint
was rewritten or re-signed, and no new Quote is claimed for that post-hoc check.

The final live case has **225 fresh verified swtpm Quotes and 225 local
trainings** across three separate five-round trajectories: clean containment,
DBA under the original enforced head, and DBA under the bounded head. This is
a known-seed runtime replication with three attack rounds and two continuations,
not one fifteen-round chain or a held-out efficacy campaign. The runtime's
configured quorum is 10; the offline pilot's quorum is 8. All rounds and all
three final campaigns verify. Successors really train from their own preceding
checkpoint, and original client signatures continue to bind those bases.

The 10 bounded live rounds reconstruct **exact original-to-report-to-exported
checkpoint bytes**, and **145 direct
individual-removal certificates** pass. Seven mutations on disposable copies
are rejected: clipping factor, original-update reference, current audit result,
predecessor history, client signature, signed mass and predecessor checkpoint.
The unmodified copy verifies. Both attacked live controls have zero full-trigger
ASR in this short case; no live ASR mitigation advantage is inferred from it.
The numerical containment improvement comes from the separate offline adaptive
experiment. Only selected components are measured by the declared swtpm profile;
physical TPM, entire-host trust and semantic data correctness are not claimed.

## Cost, incidents and reproducibility

Measured adapter wall times are retained per round. They include aggregation,
its reconstruction and removal certificates, excluding local training and head
scoring. They were collected under shared computational load, so they are not
isolated microbenchmarks or a paired speedup claim across different active bases.
Median/p95 milliseconds: `{"bounded-envelope": {"median": 430.5743770019035, "p95": 456.5227806015173}, "envelope": {"median": 8.192659501219168, "p95": 10.004030349955428}, "fedavg": {"median": 8.533350002835505, "p95": 9.736825652362313}}`.
Live context-to-checkpoint wall times have their own broader declared scope.

The first two controllers stopped before scoring due to a missing serialization
import, after 60 combined local training/replay calls; partial outputs and
controllers are retained. A historical signature-check helper then corrected
the enrollment field access before deriving any output. The initial live trial
is retained separately: numerical string indices could sort lexically rather
than in input order with over ten clients. The final backend zero-pads those
indices and enforces exact report/runtime array agreement before creating a
checkpoint; five multi-input regressions cover this. Its source and fresh TPM
evidence were regenerated. An external certificate helper initially assumed
quorum 8 and was corrected to read 10 from the signed live contract. No model
or result is changed by that reporting correction.

Clipping is an established component, already present in the reproduced
literature baseline. This is not claimed as a novel defense or a new SOTA
comparison. The thesis contribution concerns authenticated transformations,
explicit influence assumptions and reproducible quantitative diagnosis.
The 119-file final source, predecessor source releases, controllers, exact
frozen image, public artifact closures and local analyst-signed completion are
retained. Private keys/TPM private state are excluded from public closures.
The signature is local integrity, not independent witness time or certification.
Receipt completeness remains relative to supplied client evidence; trusted
deadline/delivery and an independent append-only witness are not added.
The ToN-IoT work and the actual thesis remain deferred in this implementation
step. See [SUMMARY.json](../results/revision-bounded-influence-validation-v1/SUMMARY.json) and [THESIS_HANDOFF.md](../results/revision-bounded-influence-validation-v1/THESIS_HANDOFF.md).
