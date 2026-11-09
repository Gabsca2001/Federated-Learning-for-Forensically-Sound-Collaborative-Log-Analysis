# FLTrust transfer: verified small-storage exploratory result

This completed screen applies the FLTrust aggregation equation to existing
ten-epoch Adam client endpoint updates. It is not a full reproduction of the
original FLTrust training protocol or a newly defended trajectory campaign.
The source method is [Cao et al., NDSS 2021](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_6C-2_24434_paper.pdf).

## Fixed protocol and data roles

Two selected non-IID failure seeds, both robust and capped source histories,
four clean/attack modes and rounds1/5/10/15 yield64 contexts, with56 distinct
seed/base/update input sets. Three fixed root draws and two server-training
methods yield384 root configurations. Draws overlap and histories share inputs;
counts are descriptive observations, not independent campaign replications.

Sixty original server-validation rows, ten per class, are reserved as the root
pool. Each draw uses48 rows, eight per class. All sixty are excluded from new
metric calculation, leaving3163 evaluation rows. Pool and evaluation IDs are
disjoint from client training and original test IDs. The test file is inspected
only to check ID separation: no test predictions or test metrics are calculated.
Correct root labels and absence of poisoning are experimental assumptions.
Clean here includes labelled attack classes; it does not mean benign-only data.

This is reused Data24 validation, not newly acquired trusted data or an untouched
holdout. Its rows were previously exposed to model selection, indicator scoring
and attack-query evaluation. Historical adaptive updates were chosen against
their source defenders, not adaptively against FLTrust. No new client training
or new defender-specific adaptive attack is claimed.

## Formula and deliberately distinct transfers

Eligible client deltas receive max(0,cosine(delta_i,root_delta)), with no
sample-count multiplier. Positive scores are normalized, and each entire local
delta vector is scaled to the root vector norm before averaging. There is no
per-tensor clipping in this FLTrust rule. Endpoint signs are local-minus-base
for both server and clients, so the update is added to the base checkpoint.
Zero root norm or zero positive-score sum is explicitly undefined.

SGD1 trains the root with one unweighted32-row SGD step at learning rate.001.
Adam10 uses ten Adam epochs on the48 root rows, batch128 and learning rate.001,
with inherited global training class weights. SGD1 is a paper-style root update
paired with historical Adam clients; Adam10 is an explicit compatibility
adaptation. Neither silently receives the original paper's empirical or formal
guarantees. Both use global step1 without performance-based tuning.

Controls are reconstructed robust/capped on the same inputs, root-only training,
and the robust direction rescaled to the actual FLTrust output norm. The last
isolates a change in direction from merely reducing step length. The root-only
control exposes the extra trusted-data budget, but its step norm can differ.

## Results

All384 raw formula outputs are defined. Fifty-four have fewer than ten
positive-score contributors, although all fifteen source admission prerequisites
passed under the software trust assumption. Such outputs do not establish
compatibility with the runtime positive-contributor quorum. They are retained,
not counted as successful operational continuations or silently repaired.

The following comparison pools the three root draws and concerns108 actually
manipulated context/draw observations per server-training variant. Worst ASR
means the maximum over the full trigger and the three individual components.
These are one-step effects on frozen source parents, not trajectory ASR peaks.

| Root method | Lower ASR than norm-matched robust | Higher | Equal | Mean ASR difference (points) |
| --- | ---: | ---: | ---: | ---: |
| SGD1 | 3 | 2 | 103 | -0.0021 |
| Adam10 | 18 | 9 | 81 | -1.1503 |

For SGD1, the largest improvement against the norm control is0.1731 points.
All three improving observations are below the positive-score quorum; among
the100 qualifying active comparisons there are zero improvements, two
worsenings and98 ties. The apparent advantage against the much larger capped
step is therefore not evidence of a useful new directional defense.

Adam10 has larger mixed effects: the largest improvement against norm-matched
robust is28.6209 points and the largest worsening15.2337 points. Restricting to
the94 qualifying active comparisons leaves16 improvements, eight worsenings
and70 ties. On clean contexts, however,42/48 lose more than two F1 points
against the norm-matched control, with worst loss11.1074 points. Relative to
unscaled robust,36/48 exceed two points, worst loss10.5267. Adam10 also never
improves attack ASR over root-only in these observations:24 are worse and84 tie.
Root-only has a different step norm and is not a federated solution by itself.

The three root draws, all controls, below-quorum outputs and all unfavorable
observations remain in aggregate.csv and comparisons.csv. No winning reference
or training variant is selected, and no operational default is changed.

## Additional clean-only objective diagnosis

Applying inherited class weights to an already balanced root changes its loss
emphasis: exfiltration receives31.8853% and multi_tactic5.0298% of nominal
class loss weight, versus16.6667% each with an unweighted balanced loss. This
is a plausible contributor, not a causal explanation of every attack outcome.

A separate post-hoc protocol fixes an unweighted Adam10 ablation on ALL sixteen
clean contexts and ALL three original draws. It performs no new attack or test
inference. The continuation condition requires every clean case/draw to keep
ten positive contributors and lose at most two F1 points versus both robust and
capped controls. Results are stored in revision-fltrust-root-objective-diagnostic-v1.

Removing the weights improves F1 in37/48 comparisons with weighted Adam10 and
worsens three, but does not solve the problem:34/48 still lose more than two
points against robust,40/48 against capped, and six fall below quorum. Worst
losses remain10.3817 and11.2654 points. The fixed clean continuation condition
fails. No further attacked evaluation of this ablation is opened.

This limits the tested transfers, not all possible FLTrust deployments.
Reference representativeness, client/server optimizer compatibility and the
availability contract need separate work before a new full campaign is justified.

## Verification, costs and preservation

Sixteen focused tests pass: eight new FLTrust numerical tests and eight prior
delta-blending tests. Generation repeats six root fits; verification repeats all
384 planned fits, reconstructs exported outputs, checks1280 metric sets,
replays40 selected prediction-metric sets, rehashes1216 input references and
rejects coefficient and ASR mutations. Separate vector/count arithmetic is used,
but root training and selected inference reuse the same numerical dependencies.
This is not independent-implementation certification. The clean-only ablation
also repeats all48 new root fits and recomputes F1 from confusion counts.

The original138 generation-source pins, publication files and130-module core
identity are unchanged. The two new server-training variants, references and
limits remain separately named. Existing experiments, defaults, thesis sources
and datasets are not rewritten or deleted.

Only metadata, coefficients, hashes and metrics are stored; model tensors and
datasets are referenced in place. Root checkpoints are reconstructed from pinned
data and deterministic training, rather than copied hundreds of times. All
phases enforce a64 MiB combined output budget and an8 GiB free-host-space floor.
The final Windows mirror is byte-checked. This is not a self-contained recovery
archive; original inputs remain required. Context wall-clock timing includes
training/inference on the shared machine and is not isolated deployment latency.
