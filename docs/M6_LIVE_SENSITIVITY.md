# Exploratory live downweight-threshold sensitivity

> **Completion update — 2026-09-30:** all four adaptive extension pairs are verified.
> The [five-seed report](../results/m6-adaptive-multiseed-v1/README.md) includes paired endpoints,
> trajectories and admission counts. Selected test ASR is 0/669 in both arms for every seed.
> The mean adaptive-minus-clean macro-F1 difference is +0.4038 pp across all five
> seeds (+0.1367 pp for the four new seeds). These are descriptive outcomes, not
> proof of universal robustness or beneficial poisoning. Earlier running/pending
> statements below are historical. The original locked protocol is unchanged.


> **Current status (2026-09-29):** the active-policy five-seed comparison, fixed-signal
> sensitivity, live +10% sensitivity, adaptive frozen pilot, signed smoke and paired
> v4 seed341593 are completed. The four additional adaptive seed pairs are running;
> their results are not yet available. See [current result index](../results/README.md)
> and [publication checklist](PUBLICATION_READINESS.md). Dated preparation, stopped,
> pending and running notes below are historical execution records, superseded by
> the later completion/recovery entries. Original locked protocols remain unchanged.

Prepared 2026-09-25; campaigns not yet executed at preparation time.

The fixed-signal replay motivated one candidate, not a proven improvement:
raise the gated-composite downweight threshold by 10%, from 0.2748970485340289
to 0.3023867533874318. Quarantine threshold 0.4091547031572923, retained factor
0.5, trust weight 0.5, indicator calibration and all integrity/trust vetoes stay
unchanged. The reference config and historical workspaces remain untouched.

## Execution gate

```bash
bash scripts/run_m6_downplus10.sh pilot
```

This provisions two fresh M4 namespaces and performs two 30-round trajectories,
clean/disagreement, seed 341593. After technical verification, continue with:

```bash
bash scripts/run_m6_downplus10.sh remaining
```

The remaining stage runs eight campaigns for seeds 342593, 343593, 344593 and
345593. Completion of the pilot is an integration gate, not a favorable-score gate:
continue regardless of favorable or unfavorable outcomes, unless technical errors
require investigation. Scripts stop on errors and refuse existing destinations.
Never blindly rerun after an interruption. No source code changes are required.

All runs use the original paired CPU partitions/configurations, 30 rounds, four
workers, refresh interval three and identical controlled attack assignments.
The ten original gated campaigns are the predeclared comparator; do not choose
alternative reruns based on scores. The JSON lock binds their manifests and the
variant/runner/preflight. Preflight also verifies the original frozen experiment.
The new policy config is copied into the runtime image and bound in the signed
round contract by the existing M5 code. Only the variant id/threshold change.

To avoid Docker pool exhaustion, the wrapper stops its TPM containers after
successful verification and removes only that campaign's empty trust bridge.
It never removes TPM volumes or artifact files. Before preparation one unused
smoke sequential/clean network was inspected (zero attachments) and removed to
free one subnet. No active network was removed.

## Evaluation and limits

Compare validation-selected checkpoints, benign quarantines/downweights, unsafe
retained counts and effective weights, separately by condition and paired by seed.
Report all five differences, means and uncertainty; treat rounds/contributions as
repeated observations within a seed. Include validation curves and selected rounds.
The existing M5 finalizer also produces selected-checkpoint test metrics. These
must be labelled exploratory: prior test results were already seen and the candidate
was chosen after replay. Neither new seeds nor new training restore an untouched
confirmation test. Do not retune this variant based on new scores.

The attack includes signed anomalous updates and controlled trust counterfactuals,
not new genuine Quote failures. A higher downweight threshold does not prove safety
against adaptive attacks. The current primary reference remains original gated.
New M7/M8 preservation/explanation extensions are separate gates. Results and figures
will be added after completed campaign verification; no performance claim is made now.

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
