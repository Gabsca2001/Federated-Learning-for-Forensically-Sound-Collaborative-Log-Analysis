# Clean-reference coherence: completed diagnosis and decision

This closes the bounded clean-only diagnosis following the FLTrust transfer.
No new attack inference, test prediction or defended multiround history is
generated. The prospectively fixed clean continuation gate fails. No full
follow-up is started and no operational default is changed.

## Scope and controls

The study uses all four previously selected clean source histories, two non-IID
seeds, two source operators and rounds1/5/10/15:16 contexts. Each uses all three
fixed48-row root draws and the same3163 evaluation rows as the prior screen.
Data splits and prior exposure qualifications remain unchanged. Repeated roots
and overlapping histories are not independent campaign replications.

The controller reads original honest client rows to compute diagnostic gradients.
Those oracle quantities and local class distributions are not claimed available
to an operational federated server. All cases are free of scripted manipulation;
the labelled data still contain ordinary intrusion classes.

## Distinct objectives

Let n_ic count class c at client i, n_i=sum_c n_ic, N=sum_i n_i, and w_c be the
original fixed class weights. Define s_i=sum_c n_ic w_c. The deterministic
full-batch local weighted loss is

L_i(theta) = sum_{r in D_i} w_{y_r} ell(theta;r) / s_i.

The sample-weighted mixture L_FA=sum_i(n_i/N)L_i differs in general from the
pooled weighted loss with denominator sum_i s_i. Their normalized class masses
are respectively

T_FA(c) = sum_i (n_i/N) n_ic w_c / s_i,
T_pool(c) = sum_i n_ic w_c / sum_i s_i.

For root sampling frequency q_c, class weights v_c=T(c)/q_c match a chosen
class mass in the full root batch. This corrects the marginal loss objective;
it cannot recreate missing within-class examples or ensure a representative
gradient. Root class conditionals can still differ from client conditionals.

Both targets are retained, alongside inherited and unweighted root losses.
The local-mixture correction uses private-data diagnostic information and is
not selected as an operational candidate. Only the pooled-corrected Adam root
with actual historical Adam updates is eligible for the fixed continuation gate.

## Gradient and endpoint separation

All diagnostic gradients are float64, full-batch, evaluation-mode weighted-mean
cross-entropy derivatives. Dropout is disabled. They are not the stochastic
training-mode gradients or parameter deltas produced by ten Adam epochs.
Oracle controls use the exact honest local-risk mixture descent. Direction-only
controls match the corresponding honest baseline step norm; they are explanatory
controls rather than hidden learning-rate changes to the candidate.

On these16 selected clean parents, the cosine between the sample-weighted mean
historical Adam delta and instantaneous honest local-risk descent ranges from
-0.1486 to0.2743, with mean0.0323. This quantifies a large directional difference.
Multiple local steps, adaptive preconditioning, minibatching, dropout and finite
parameter movement differ together, so it is not a causal attribution to Adam
alone or evidence that Adam is intrinsically defective.

The root-gradient alignment with the honest local-risk mixture improves when
the marginal objective is corrected:

| Root class objective | Mean cosine | Minimum cosine |
| --- | ---: | ---: |
| Inherited weights on balanced root | 0.4463 | -0.7803 |
| Unweighted balanced root | 0.4543 | -0.7859 |
| Pooled weighted target correction | 0.6698 | -0.4493 |
| Exact local-risk class-mixture correction (diagnostic oracle) | 0.8080 | 0.3871 |

These means concern48 context/draw gradients per objective. They do not establish
attack resistance. Pooled and local-risk full gradients themselves have mean
cosine0.8136 and minimum0.2270 here, supporting the need to distinguish objectives.

## Quorum counterexamples with exact references

With the exact honest local-risk reference and coherent honest full-batch gradient
inputs, FLTrust has fewer than ten positive-score contributors in4/16 clean
contexts. No F1 loss exceeds two points against the matched gradient-FedAvg
baseline. Positive cosine support is unaffected by the positive norm scaling.

With the same exact-gradient reference applied to historical Adam endpoints,
5/16 contexts fall below quorum and10/16 lose more than two F1 points against
the matched robust control. Thus better root sampling alone cannot guarantee
both the existing availability contract and useful transfer to these endpoints.
The quorum of ten is the framework's requirement, not an added claim about
the original FLTrust algorithm, whose raw formula can remain defined below it.

## Candidate result and fixed decision

The actual pooled-corrected48-row Adam root has48 defined clean results:

- Four have fewer than ten positive-score contributors.
- Thirty lose over two F1 points relative to robust; worst loss10.3817 points.
- Thirty-six lose over two points relative to capped; worst loss11.3602 points.
- Thirty-six fail at least one prospective clean condition.

The local-mixture-corrected diagnostic Adam root still loses over two points
in30/48 comparisons against robust and36/48 against capped, with three
below-quorum results. It is not an operational fallback.

The continuation rule required every actual small-root candidate result to be
defined, preserve ten positive contributors and lose no more than two F1 points
against both original same-input controls. It fails. No reference, threshold,
quorum or failure endpoint is changed after observing the result. No new attack
sweep or full multiround campaign is opened.

This closes this compatibility-transfer iteration. A future coherent optimizer
or availability/recovery contract would be a separately declared research
revision with its own clean baselines and fresh attack validation. The current
formal derivation, historical policy names and measured core are unchanged.

## Verification and preservation

Fourteen focused tests pass: six objective/gradient tests and eight FLTrust
numerical tests. Generation computes432 diagnostic gradients,96 root optimizer
fits and16 real-model directional finite-difference probes on the smooth final
bias. A separate checker verifies528 metric sets, repeats30 client gradients,
12 root gradients and six optimizer/metric cases, and rejects changed F1,
quorum counts and objective weights. The finite differences test that head
direction, not every parameter. Numerical libraries and selected inference are
shared; no independent-implementation or general-security certificate is claimed.

All138 original generation pins, publication checksums and the measured130-module
core identity remain unchanged. Only hashes, scalar diagnostics, coefficients
and metrics are stored. Original inputs remain required for reconstruction.
A64 MiB result budget and8 GiB free-host floor are enforced. New thesis edits,
external witness deployment and ToN-IoT remain outside this task.
