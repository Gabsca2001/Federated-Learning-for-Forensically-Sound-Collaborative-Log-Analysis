# Baseline and DBA validation closure

Date: 2026-11-03. Step 1 of the agreed revision sequence. ToN-IoT is deferred.

## Result and unresolved empirical weaknesses

The baseline comparison is now consolidated with reproducible numerical checks,
operational selection counts, frozen-model test outcomes and measured cost.
The original composite succeeds on the retained distributed-trigger outputs but
does not remove an inherited complete-trigger backdoor: at round 10 its mean
test ASR is **88.21%**, versus **96.97%** for FedAvg. On separately referenced
clean histories it excludes **15/675 IID** and **16/675 non-IID** updates.
These negative outcomes remain part of the result.

The current individual-envelope policy has zero clean exclusions in the added
common-input check and better non-IID poisoned-update coverage than the old
fixed-reference composite. This comparison does not prove general superiority:
the methods have different clean-reference/data requirements, and reaggregating
one round cannot undo the poisoned incoming model. Automatic live deployment,
adaptive-attack resistance, group discovery and clean-state restoration remain
separate validation obligations.

## Preserved protocols and audit scope

The original nine authenticated cases cover clean, distributed and complete-trigger
conditions at three seeds (341593, 342593, 343593), 15 rounds and 15 clients.
Rounds 1–10 inject the attack; rounds 11–15 continue clean local training.
Clients 01/06/11 poison 50% of their selected examples toward the benign label.
The distributed trigger divides features 13/17/24 across clients; the complete
variant applies all three to each attacker's selected examples. Selected example
IDs and label-flip counts match between paired modes; their feature-edit budgets
differ. They are not equal feature-budget attacks.

The MLP, incoming initial checkpoint, partitions, scaler, local Adam protocol
(10 epochs, batch 128, learning rate .001), validation/test records and auxiliary
set are preserved. Server validation has 3,223 rows; test has 4,937 rows; the
fixed WeiDetect auxiliary subset has 2,238 rows selected using the initial
reference model. The experiment remains Data24, not an external-dataset study.

Only **FedAvg drives each source training history**. The other seven methods
reaggregate the same incoming checkpoint and local updates. Their outputs are
conditional single-round comparisons, not independently trained defense
trajectories. The original software admissibility assumption is retained;
there are no new TPM Quotes in this step.

Checks performed now:

- Authenticate all nine original cases and verify 2,025 updates across 135 rounds.
- Recompute **1,080 aggregate model exports byte-for-byte**.
- Recompute all **144 original fixed test endpoints**.
- Authenticate six actual-gradient cases and reproduce **53 aggregate exports byte-for-byte**.
- Add 180 common-input contexts, **900 conditional outputs** and **120 test endpoints** with independent historical clean references.
- Measure aggregation, scoring and current-policy costs in sequential, single-threaded jobs.

`protocol-before-audit-and-benchmark.json` and the later secondary protocol were
frozen before their respective execution. The old endpoint report is bound and
replayed now; no earlier signing or trusted creation time is implied. Original
reports and failed/partial executions are preserved.

## Original shared-update outcomes

All percentages below are mean ± sample standard deviation over three seeds.
The component column is the largest component-wise seed mean. It is not the
complete-trigger ASR. See [all clean and attacked R10/R15 endpoints](TEST_ENDPOINT_SUMMARIES.md)
and [machine-readable endpoint records](fixed-test-endpoints.json).

### Distributed trigger, round 10

| Round | Method | Clean accuracy (%) | Macro-F1 (%) | Complete ASR (%) | Max mean component ASR (%) |
| --- | --- | --- | --- | --- | --- |
| 10 | FedAvg | 97.77 ± 0.09 | 92.67 ± 1.13 | 44.09 ± 3.75 | 0.000 |
| 10 | Coordinate median | 97.62 ± 0.04 | 91.45 ± 0.27 | 0.02 ± 0.03 | 0.000 |
| 10 | Trimmed mean | 97.62 ± 0.03 | 91.33 ± 0.15 | 0.04 ± 0.03 | 0.000 |
| 10 | Multi-Krum | 97.60 ± 0.04 | 91.74 ± 0.41 | 0.00 ± 0.00 | 0.000 |
| 10 | Bulyan | 97.43 ± 0.02 | 91.00 ± 0.12 | 0.00 ± 0.00 | 0.000 |
| 10 | FLAME adaptation | 97.08 ± 0.53 | 89.70 ± 1.78 | 0.00 ± 0.00 | 0.000 |
| 10 | WeiDetect adaptation | 97.66 ± 0.04 | 92.40 ± 0.31 | 0.00 ± 0.00 | 0.000 |
| 10 | Original composite | 97.65 ± 0.04 | 92.18 ± 0.50 | 0.00 ± 0.00 | 0.000 |


Coordinate median and trimmed mean retain small nonzero ASRs; rounding them to
zero would be incorrect. All eight methods have zero complete-trigger ASR at
round 15 in this distributed source condition, including FedAvg after five
unpoisoned continuation rounds. That observation is neither a recovery proof
nor evidence of unique defense benefit.

### Complete trigger, round 10

| Round | Method | Clean accuracy (%) | Macro-F1 (%) | Complete ASR (%) | Max mean component ASR (%) |
| --- | --- | --- | --- | --- | --- |
| 10 | FedAvg | 97.50 ± 0.23 | 91.57 ± 0.89 | 96.97 ± 0.52 | 0.086 |
| 10 | Coordinate median | 97.49 ± 0.05 | 91.16 ± 0.30 | 86.57 ± 3.18 | 0.010 |
| 10 | Trimmed mean | 97.55 ± 0.05 | 91.13 ± 0.31 | 89.70 ± 2.12 | 0.010 |
| 10 | Multi-Krum | 97.28 ± 0.42 | 90.16 ± 1.86 | 63.69 ± 8.73 | 0.000 |
| 10 | Bulyan | 97.28 ± 0.11 | 90.55 ± 0.70 | 68.05 ± 1.60 | 0.000 |
| 10 | FLAME adaptation | 96.83 ± 0.45 | 89.01 ± 2.05 | 64.15 ± 6.85 | 0.000 |
| 10 | WeiDetect adaptation | 97.72 ± 0.30 | 93.27 ± 2.46 | 95.09 ± 1.84 | 0.029 |
| 10 | Original composite | 97.62 ± 0.09 | 91.90 ± 0.55 | 88.21 ± 0.22 | 0.000 |


Every method retains substantial full-trigger ASR here despite small component
ASRs. The poisoned incoming state helps explain why excluding current poisoned
updates need not clear the full backdoor. At round 15 mean ASR remains 11.81%
for FedAvg, 2.69% for FLAME, 23.93% for WeiDetect and 11.37% for the original
composite. These are conditional outputs on the continuing source histories.
There is no claim of complete removal.

### Operational exclusions and downweights

Ground truth is the actual row-edit record for the current round. A client that
stops poisoning is currently clean; inherited contamination is not relabelled
as a new intentional poisoning action. JSON also separates never-attacker
clients. Strict exclusion means zero aggregation mass/absence from the selected
set. Downweighting and FLAME clipping are separate operations.

Distributed attack, rounds 1–10:

| Method | Poisoned excluded / opportunities | Currently clean excluded / opportunities | Clean downweighted | Poisoned downweighted |
| --- | --- | --- | --- | --- |
| FedAvg | 0/90 | 0/360 | 0 | 0 |
| FLAME adaptation | 90/90 | 111/360 | 0 | 0 |
| WeiDetect adaptation | 67/90 | 23/360 | 0 | 0 |
| Original composite | 90/90 | 1/360 | 13 | 0 |


Complete-trigger attack, rounds 1–10:

| Method | Poisoned excluded / opportunities | Currently clean excluded / opportunities | Clean downweighted | Poisoned downweighted |
| --- | --- | --- | --- | --- |
| FedAvg | 0/90 | 0/360 | 0 | 0 |
| FLAME adaptation | 90/90 | 114/360 | 0 | 0 |
| WeiDetect adaptation | 36/90 | 54/360 | 0 | 0 |
| Original composite | 77/90 | 1/360 | 19 | 12 |


On the original clean cases, FLAME excludes 276/675 and WeiDetect 135/675.
The old composite excludes 0/675 but downweights 90/675. Its clean references
and thresholds are fitted to the same clean-round indicators being evaluated:
zero strict exclusions is an **in-sample calibration result**, not an independent
false-positive estimate. The attacked cases use paired clean histories as an
experimental prior. FedAvg's zero exclusions mean participation, not malicious
client detection. Client-level detection metrics are unavailable in the retained
coordinate median/trimmed mean/Multi-Krum/Bulyan reports and are not invented.

## Secondary comparison with separate clean references

To check the calibration weakness, a secondary analysis was predeclared on 12
previously evaluated shadow-FedAvg histories: IID/non-IID × clean/distributed ×
three seeds, 15 rounds each. Each attacked history has 12 attack rounds (108
poisoned opportunities pooled over three seeds). Client assignments differ
across cases. This is a secondary analysis of existing trajectories, not
new prospective training or an untouched external test.

The original composite uses the earliest predeclared historical clean calibration
seed in each cohort (451593 IID, 454593 non-IID), matched by round index.
References are not chosen by evaluation outcomes. Original hyperparameters,
FLAME noise .01, WeiDetect K=12, and the frozen individual-envelope policy stay
fixed. Envelope decisions are authenticated and rechecked in its cost benchmark.
Both weighted conditional variants use a common delta-FedAvg backend here;
the original nine-case composite uses its original Flower weighted-model backend.
This numerical profile difference is explicit.

| Cohort | Method | All-clean exclusions / 675 | Attacked: poisoned exclusions / 108 | Attacked: currently clean exclusions / 567 |
| --- | --- | --- | --- | --- |
| iid | FedAvg | 0 | 0 | 0 |
| iid | FLAME adaptation | 278 | 108 | 196 |
| iid | WeiDetect adaptation | 135 | 100 | 35 |
| iid | Fixed-reference composite | 15 | 108 | 5 |
| iid | Individual envelope | 0 | 96 | 0 |
| non-iid | FedAvg | 0 | 0 | 0 |
| non-iid | FLAME adaptation | 311 | 58 | 237 |
| non-iid | WeiDetect adaptation | 135 | 9 | 126 |
| non-iid | Fixed-reference composite | 16 | 26 | 7 |
| non-iid | Individual envelope | 0 | 77 | 0 |


The 15/675 and 16/675 old-composite clean exclusions correspond to **2.22%**
and **2.37%**. Zero envelope clean exclusions is limited to these observed
cases. In attacked non-IID contexts, FLAME excludes 58/108 poisoned updates
and 237/567 currently clean updates; WeiDetect 9/108 and 126/567; the old
composite 26/108 and 7/567; the envelope 77/108 and 0/567.

The richer envelope uses two frozen clean predictors and individual null banks;
the old composite uses one matched clean reference; WeiDetect needs labelled
auxiliary data; FLAME does not use those labelled references. These information
budgets differ. This is not an equal-information ranking of methods.

[All 120 secondary test outcomes](secondary-test-results.json) and their
[40 three-seed summaries](SECONDARY_TEST_SUMMARIES.md) include full/component
ASR, accuracy and macro-F1. Examples of conditional outputs on the attacked
source histories:

- iid: R10, Individual envelope conditional test ASR 0.00 ± 0.00%, clean accuracy 97.50 ± 0.15%.
- iid: R10, FedAvg conditional test ASR 21.89 ± 24.76%, clean accuracy 97.35 ± 0.39%.
- non-iid: R10, Individual envelope conditional test ASR 31.24 ± 54.10%, clean accuracy 96.10 ± 0.41%.
- non-iid: R10, FedAvg conditional test ASR 32.75 ± 56.73%, clean accuracy 96.38 ± 0.14%.

An envelope action applied to an already poisoned FedAvg history is different
from the active envelope trajectory in the earlier 36-episode study. The earlier
active zero-ASR result cannot be substituted for this common-input comparison.
Neither comparison demonstrates semantic malice or historical clean-state
reconstruction. The test fold has been used in earlier studies and is not
presented as a pristine new holdout.

## Literature fidelity and explicit adaptations

FLAME's model-cosine clustering, update-norm clipping, averaging and Gaussian
noise stages are represented. This MLP/Data24 adaptation uses fixed noise
factor .01 and deterministic execution seeds; no new differential-privacy
guarantee or full original experimental replication is claimed.
[Primary source: FLAME, Algorithm 1](https://www.usenix.org/system/files/sec22-nguyen.pdf).

WeiDetect's auxiliary F1, Weibull scoring and fixed top-K selection are represented.
K=12 of 15 forces three removals even in all-clean rounds; operational pruning
is not proof of maliciousness. All 135 retained rankings equal seeded F1 top-K.
**88/135** fits are degenerate and use the declared fallback, not successful
Weibull estimation. This dataset, architecture, zero/tie handling and optimizer
are explicit adaptations to the shared-update protocol.
[Primary source: WeiDetect v1, Algorithm 3](https://arxiv.org/html/2504.04367v1).

FedGradTrace's printed Eq. (2) and Eq. (3) define different recurrences: the former
has generally nonunit coefficient sum and rescales the incoming model; the latter
uses normalized trajectory norms in a gradient step. They are retained as
separate literal adaptations. The MLP adapter does not reproduce the full
DistilBERT/FedXLog system. It is not a native malicious-client classifier.
[Primary source: FedXLog/FedGradTrace](https://www.techscience.com/cmc/v87n3/66965/html).

### Actual-gradient cases and interrupted execution

The separate gradient experiment has 10% poison fraction, one actual full-snapshot
class-weighted gradient per client/round, three-snapshot histories and global
SGD learning rate .001. It uses no substituted Adam parameter deltas. Its
protocol differs from the 50%/local-Adam DBA study and is not pooled into that
efficacy table.

| Case | Completed rounds | Final clean accuracy (%) | Final complete ASR (%) | Untriggered non-target → target (%) | Coefficient sum |
| --- | --- | --- | --- | --- | --- |
| clean-gradient_fedavg | 10 | 96.68 | 0.00 | 0.00 | 1 |
| clean-literal_eq2 | 10 | 26.09 | 0.00 | 0.00 | 0.468793 |
| clean-literal_eq3 | 10 | 96.68 | 0.00 | 0.00 | 1 |
| distributed-gradient_fedavg | 10 | 96.56 | 0.00 | 0.00 | 1 |
| distributed-literal_eq2 | 3 | 44.68 | 100.00 | 100.00 | 10247.5 |
| distributed-literal_eq3 | 10 | 96.06 | 0.00 | 0.00 | 1 |


The attacked literal Eq. (2) completes only three of ten requested rounds.
At round 3, both triggered and untriggered non-target examples map to the target
at 100%; this is broad prediction collapse, not evidence of a selective stealth
backdoor. Its coefficient sum is about 10,247.55. The partial round-4 Eq. (2)
model reaches maximum absolute parameter 1.37e30. All three saved alternative
round-4 models have finite parameters but NaN validation loss on that unstable
incoming history. The failure is retained and not repaired by silently changing
the recurrence. No valid fourth-round or ten-round Eq. (2) result is claimed.

A simple source-equation check with incoming scalar 2, zero current gradients
and two trajectory norms of 2 returns 4 under literal Eq. (2), 2 under Eq. (3).
This documents the rescaling difference. The gradient FedAvg control already
has zero ASR throughout its attacked run; Eq. (3)'s zero ASR therefore does not
establish attack mitigation. The clean Eq. (2) accuracy collapse is also retained.

All 53 completed aggregate exports replay exactly. Floating diagnostic norms and
coefficients agree at declared relative tolerance 5e-14 / absolute 1e-15
(maximum observed relative discrepancy 2.16e-15); this tolerance is not applied
to model bytes. [Full diagnosis and records](gradient-audit.json).

## Measured computation cost

Measurements use one CPU thread, preloaded inputs and separate sequential
processes per method/scope. Timers cover both wall and process CPU time.
Kernel rows cover all 135 contexts × three repetitions; full scoring rows cover
the same nine cases at rounds 1/10/15 (27 contexts × three). One warm-up is
excluded per method/scope. Output equivalence is checked outside the timer.
There are **3,240 timed kernel calls** and **162 full scoring calls**.

| Method | Scope | Contexts × repeats | Median wall (ms) | 95th percentile (ms) | Process peak RSS (MiB) |
| --- | --- | --- | --- | --- | --- |
| WeiDetect adaptation | full | 27 × 3 | 192.895 | 299.786 | 786.7 |
| Original composite | full | 27 × 3 | 269.115 | 371.448 | 789.4 |
| FedAvg | kernel | 135 × 3 | 2.952 | 4.313 | 777.7 |
| Coordinate median | kernel | 135 × 3 | 5.353 | 6.562 | 778.2 |
| Trimmed mean | kernel | 135 × 3 | 4.982 | 6.468 | 777.6 |
| Multi-Krum | kernel | 135 × 3 | 5.881 | 7.343 | 799.7 |
| Bulyan | kernel | 135 × 3 | 9.075 | 11.403 | 800.1 |
| FLAME adaptation | kernel | 135 × 3 | 3.995 | 5.572 | 788.6 |
| WeiDetect adaptation | kernel | 135 × 3 | 0.899 | 8.652 | 774.5 |
| Original composite | kernel | 135 × 3 | 0.218 | 0.417 | 772.9 |


Kernel WeiDetect uses cached auxiliary F1 and kernel composite uses cached
masses. Full WeiDetect includes 15 model evaluations on 2,238 auxiliary rows;
full composite includes base/client inference on 3,223 validation rows,
indicators, scoring, policy and aggregation. Neither cached kernel latency nor
process peak RSS represents complete deployment cost. File loading, transport,
local training, clean-reference campaign generation, TPM and first imports are
outside these scopes. Process RSS includes common Torch/Flower libraries,
inputs and allocator retention; it is not incremental defense allocation.
Repeated contexts/samples are dependent; no statistical confidence interval
or production latency guarantee is inferred.

The latest policy is measured separately on its own 180 source contexts, using
three independent stateful chains per case. Each timed operation advances
exactly one round and includes both frozen predictors, support checks, current
envelope decisions and selected-contributor aggregation. It does not time an
idempotent retry. There are **540 timed operations**, two excluded warm-ups.

| Cohort | Contexts × independent chains | Median wall (ms) | 95th percentile (ms) | Process peak RSS (MiB) |
| --- | --- | --- | --- | --- |
| iid | 90 × 3 | 21.480 | 25.949 | 841.2 |
| non-iid | 90 × 3 | 21.275 | 24.106 | 841.2 |


These current-policy contexts differ from the 27 original full-scoring contexts;
no paired speedup ratio is claimed. Initial predictor loading and the cost of
training/calibrating predictors are excluded.

Native-gradient server aggregation is timed separately on its 53 completed
contexts, three repetitions and one warm-up per context:

| Native gradient recurrence | Timed calls | Median server aggregation (ms) | 95th percentile (ms) |
| --- | --- | --- | --- |
| gradient_fedavg | 60 | 0.580 | 0.947 |
| literal_eq2 | 39 | 5.313 | 8.670 |
| literal_eq3 | 60 | 4.333 | 5.375 |


One representative clean full-snapshot collection over all 15 clients / 7,096
records takes median **38.736 ms** in a shared sequential runtime
(three timed collections after one warm-up). All resulting gradients exactly
match the preserved source. This performs **60 new gradient evaluations and
zero optimizer steps**. The audit process memory peak includes earlier work
and is not attributed to gradient collection alone. This limited acquisition
measurement does not estimate all network/client hardware costs.

## Evidence, implementation and next boundary

This step changes maintained reports and adds audit/measurement scripts. It does
not change production algorithms, thresholds or training protocols. The full
114-file implementation is checked against the preceding source archive. The
preceding **631-test** result remains source-applicable; the full suite is not
rerun here. New verification consists of the numerical/model/selection replays,
source authentication, benchmark checks and final integrity closure described above.

The signed completion is a local software analyst record, **not an independent
witness, trusted timestamp or TPM attestation**. Its closure binds protocols,
results, scripts, figures and source fingerprints. Earlier signed releases are
preserved. The thesis and git index remain unchanged in this step. No new
client-training campaign or ToN-IoT acquisition is performed.

The next agreed step is retrospective group validation: selected groups versus
individual removal, joint removal and benign controls, followed by genuinely
retrained later rounds where causal claims require them. Group membership
errors and the wording “compatible with coordinated behaviour” must remain
explicit. This baseline audit does not close that step, the adaptive envelope
weakness, live TPM integration, final formal alignment or thesis writing.

Figures: [test attack/utility](baseline-test-outcomes.png),
[operational exclusions](secondary-exclusions.png),
[measured cost scopes](measured-costs.png). Each also has a PDF export.
