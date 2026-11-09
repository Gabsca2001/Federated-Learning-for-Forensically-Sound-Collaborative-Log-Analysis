# Explicit capped-final aggregation: completed exploratory campaign

Completed **108/108** planned histories. The independent numerical audit reconstructed **1620 rounds**, **1440 adaptive candidate evaluations**, **810 capped coefficient certificates** and **45 historical FedAvg checkpoints**.

Combined predeclared research guards passed: **False**. Structural continuity/coefficient checks passed: **True**.

| Evaluation | Clean utility failures | Worse paired security comparisons | Strict benefits in effective raw controls | Non-IID benefits | Security guard |
| --- | ---: | ---: | ---: | ---: | --- |
| validation | 2/54 | 6/18 | 0 | 0 | False |
| test | 2/54 | 6/18 | 0 | 0 | False |

## Design and interpretation

The four arms use mandatory-trust-only admission: raw FedAvg, robust bounded aggregation, capped sample weights and capped robust weights. The capped operators retain the original admitted counts and alpha, but derive a distinct final beta after tensor clipping. Each coefficient is at most 1/9, hence any three clients have final share at most 1/3. Admission retention is not preservation of sample-proportional influence; alpha/beta total variation is reported.

Three previously problematic non-IID assignments provide 12 known clean mechanism replications. Six separately declared IID/non-IID assignments provide 96 clean/distributed/full-trigger/adaptive histories. All histories have a 15-round horizon, attacks in rounds 1–10 and unmodified continuation in rounds 11–15. The test split was used in previous work; new assignments are exploratory and do not supply an independent dataset.

The DBA controls three identities and deterministically selects ceil(0.50*N_i) of each local dataset for triggering and assignment of the benign target label, including rows already labelled benign (which are triggered without a label flip). It sets standardized feature coordinates 13, 17 and 24 to 12. The distributed variant gives each client one component; the complete-trigger variant gives each attacking client the full trigger. These are feature-space experiments; realizability as raw network traffic is not established. The adaptive variant queries alpha={0,.25,.5,1,2,4} against each actual defender, optimizing validation worst-trigger ASR without a clean-utility constraint. Alpha zero is an unmodified export, and values above one amplify the poisoned direction.

The adaptive search uses an experimental defender-aware validation oracle. This does not establish that a deployed attacker has access to the server validation labels or such a live API.

Effective local training uses ten Adam epochs, batch size 128 and learning rate 0.001 on CPU. The actual quorum is ten, read from runtime_admission; the inherited training-helper field of eight is not the active quorum. All methods share the pinned historical warm start and scaler; effective-settings.json records field precedence.

Paired harm is the maximum over fixed rounds of attacked worst full/component-trigger ASR minus the same method’s own clean worst-trigger ASR at that round. The historical effective-control rule requires at least 20 percentage points paired ASR increase with at most 5 points clean F1 loss at the same endpoint. Undefined results remain undefined. Full-trigger zero and final zero do not establish prevention across trigger components or over the whole history.

## Reserved attack outcomes

Cells below show cohort mean **peak / final full-trigger test ASR (%)**, with all three assignments contributing when complete. Per-assignment worst-trigger outcomes and paired effects remain in the CSV files.

| Cohort | Attack | TPM-only FedAvg | Robust bounded | Capped sample | Capped robust |
| --- | --- | --- | --- | --- | --- |
| iid | distributed | 65.67 / 4.66 | 0.00 / 0.00 | 47.66 / 0.00 | 0.00 / 0.00 |
| iid | complete-trigger | 98.07 / 53.32 | 31.08 / 0.00 | 97.62 / 53.58 | 31.08 / 0.00 |
| iid | adaptive | 100.00 / 99.97 | 0.00 / 0.00 | 53.59 / 0.00 | 0.00 / 0.00 |
| non-iid | distributed | 16.60 / 0.00 | 0.57 / 0.00 | 32.66 / 0.18 | 31.04 / 0.00 |
| non-iid | complete-trigger | 31.80 / 20.90 | 25.20 / 10.79 | 54.91 / 32.89 | 48.93 / 32.60 |
| non-iid | adaptive | 65.68 / 33.31 | 3.54 / 0.00 | 54.35 / 20.47 | 32.76 / 2.77 |

## Residual differences and measured cost

At the fixed round-10/15 endpoints, **144/144** defined own-method attacked/clean comparisons have nonzero parameter distance. The table also records untriggered test prediction differences. These differences alone do not establish harmful remaining poisoning, and zero ASR alone does not establish restoration.

attacked-clean-utility.csv also retains the untriggered-data macro-F1 loss of each attacked model against its own clean control at every fixed round. This exposes defenses that lower ASR while degrading normal classification. The predeclared clean-branch utility guards remain separately identified; no new attacked-utility threshold was fitted.

The timing table retains actual observed training, attack-search and operator times. For special operators the first uncached computation is measured by final_operator_seconds; the repeated aggregation_seconds call may be a cache lookup. Raw FedAvg has no such cache and uses its actual repeated aggregation time. Search, geometry and operator timings overlap and must not be added as disjoint components. Jobs used two concurrent CPU workers; retained historical cases keep their original timings. These are measured shared-host costs, not isolated latency benchmarks.

## Defaults, trust and scope

The standard in-round admission configuration still selects gated_composite when explicitly bound to M5. The unified witnessed profile selects tpm_only. The present study also uses tpm_only as common admission, with prerequisite trust assumed passed in software. It creates no fresh TPM quote and does not measure a new physical-TPM campaign. The old severe statistical gate can still defer upstream; the new operator does not override zero admission or trust vetoes. No default was changed and no automatic permanent client exclusion was validated.

A coefficient/norm bound is not an ASR guarantee. Clean utility, attack effectiveness and continuity are reported independently. An effective live deployment would additionally require a source-bound measured runtime for the selected operator. The thesis and ToN-IoT evaluation were left unchanged by this campaign.

Trajectory curves show the mean over three reserved assignments, with min–max shading; a curve stops when all three observations are no longer available. This descriptive range is not a confidence interval; per-assignment tables retain outliers.

## Evidence

- Frozen protocol and pre-test reporting contract are copied alongside the results.
- Complete source evidence: artifacts/revision-capped-final-v1/cases/.
- Training closure: artifacts/revision-capped-final-v1/training-complete.json.
- Cache-disabled numerical audit: artifacts/revision-capped-final-v1/verified/summary.json.
- Operational interruptions remain preserved; resource failures were not counted as attack or defense outcomes.
- cases.csv, rounds.csv, triggers.csv, costs.csv, clean-utility.csv, attacked-clean-utility.csv, paired-effects.csv, security-comparisons.csv, aggregate.csv and residuals.csv retain every planned case.
