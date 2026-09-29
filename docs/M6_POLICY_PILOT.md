# Paired active-policy pilot

> **Current status (2026-09-29):** the active-policy five-seed comparison, fixed-signal
> sensitivity, live +10% sensitivity, adaptive frozen pilot, signed smoke and paired
> v4 seed341593 are completed. The four additional adaptive seed pairs are running;
> their results are not yet available. See [current result index](../results/README.md)
> and [publication checklist](PUBLICATION_READINESS.md). Dated preparation, stopped,
> pending and running notes below are historical execution records, superseded by
> the later completion/recovery entries. Original locked protocols remain unchanged.

This new pilot keeps gated_composite as the reference and makes sequential an actual
aggregation policy in a separate trajectory. Both retain the mandatory M5 integrity and
observed-trust veto. They share the existing clean calibration without test-based tuning.
The checkpoint records the deployed aggregation strategy and its verifier recomputes it.
Historical gated-composite workspaces remain read-only and supported by their prior digest.

Run from the repository root in WSL, after activating the virtual environment:

```bash
bash scripts/run_m6_policy_pilot.sh smoke
```

Inspect all four verified one-round campaigns before running:

```bash
bash scripts/run_m6_policy_pilot.sh pilot
```

Each phase provisions four fresh M4 environments, uses the existing M4/M5 commands,
and stops on the first error. Existing destinations or Docker state cause a preflight
failure; the wrapper deliberately does not attempt recovery of partial evidence.
TPM containers are stopped only after successful verification; volumes remain intact.
The final text marker is an execution convenience, not a cryptographic verification receipt.
Do not change implementation or configs between smoke and pilot; otherwise repeat the smoke
with a reviewed new experiment identifier. No old workspace is overwritten.

The pilot fixes seed 341593, CPU, the same existing verified IID partition, 30 rounds,
4 workers, and refresh interval 3. The one-round smoke uses separate destinations.
The two conditions are clean and the existing controlled disagreement scenario: real signed
sign-flipped/amplified updates plus explicitly counterfactual failed-trust policy inputs.
This is not a new genuine Quote-failure experiment. Each policy sees its own independently
trained trajectory; identical seeds and assignments do not imply identical later updates.

After the pilot, compare selected-checkpoint test macro-F1, benign quarantines and
downweights, unsafe retained counts and effective weights. Select checkpoints on validation
only and retain failures as outcomes. A smoke result is integration evidence, not an estimate
of detection performance. Do not infer superiority from the pilot alone.

The next stage requires a separately bound five-seed runner and paired summary (two policies
by two conditions by five seeds). It has not been launched by this script. The historical
live-explanation and M8 accounting profiles remain gated-composite-specific; do not use them
to label sequential artifacts. Both pilot policies use the independent M5 campaign verifier.

## Five-seed extension

The four verified pilot campaigns at seed 341593 are retained as the first pair of
conditions/policies. Execute the remaining 16 campaigns with:

```bash
bash scripts/run_m6_policy_multiseed.sh
```

Seeds 342593, 343593, 344593, 345593 each receive one new IID partition generated
from its own CPU federation configuration. Four independent M4/M5 namespaces share
that seed's partition. M5 now accepts --federation-config, retaining federation.yaml
as the default. Its signed contexts bind the chosen configuration; M5 rejects a
partition created from a different config. CUDA M3 partitions are not reused here.

The JSON lock records source/configuration digests and the four pilot manifest
digests. The read-only preflight checks them, all pilot admission bindings, and
exact seed-only changes before starting. Parameters remain 30 rounds, four workers,
refresh interval three, fixed calibration and the same controlled disagreement.
This fresh-only wrapper stops on any error and refuses existing campaign or TPM
state; do not rerun blindly after interruption. All volumes/artifacts are retained.
The four seed blocks run serially to limit simultaneous resource use.

After all 20 campaigns verify, report every seed, paired gated-minus-sequential
macro-F1 differences separately for clean/disagreement, and benign/unsafe intervention
counts. Use five seed-level pairs, not 150 rounds or 2250 client observations, as
independent repetitions. Keep any interval explicitly conditional on this fixed
dataset/protocol. This extension does not make the simulated trust failures genuine
Quote failures. No thresholds or policy selection are tuned on these test results.

## Execution record and recovery — 2026-09-25

The four smoke and four seed-341593 pilot campaigns passed. The
[pilot snapshot](../results/m6-active-policy-pilot-v1/README.md) records exact metrics and
source hashes. In the 16-run extension, seeds 342593, 343593 and 344593 completed
all four campaigns. Seed 345593 gated/clean completed 30 rounds and its internal
verification, but Docker Hub timed out while resolving the Python base image for
the subsequent verification-only build. A retry of that build succeeded.

The root-level `resume_m6_policy_345593.sh` is incident-specific: it verifies the
already-finalized gated/clean workspace without reprovisioning it, then executes the
three untouched campaigns of seed 345593. It preserves the frozen scripts/configs
and all existing evidence. Recovery is currently in progress; do not use this
fresh-only recovery script to restart partial training after another interruption.

Raw `.log` files are ignored and none are tracked at this checkpoint. Preserve them
locally for diagnosis; Git-facing records consist of these Markdown updates plus
sanitized results and source digests. No commit or push has been performed.

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
