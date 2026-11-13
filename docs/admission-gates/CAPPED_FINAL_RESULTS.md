# Capped-final aggregation: validated results and limits

The complete frozen study contains **108/108 completed 15-round histories**.
The separate, cache-disabled numerical verifier reconstructed **1,620 rounds**,
**1,440 adaptive candidate evaluations**, **810 capped coefficient certificates**,
**216 repeated local-training checks** and **45 exactly reproduced historical
FedAvg checkpoints**. The publication checker independently checked the tables
and recomputed fixed-endpoint prediction differences in a fresh process.

The result is a useful structural improvement with an unfavorable security
tradeoff. It does **not** qualify the capped robust profile for promotion.

## What passed

All methods completed training, including the three previously problematic
non-IID assignments. The capped operators retained the full nominal admitted
sample mass, respected a quorum of ten and the one-third final coefficient ceiling for
every group of at most three clients. These coefficients apply to clipped
updates. The operator changes their relative numerical influence; this is a
transformed aggregation rule, not the original sample-proportional FedAvg rule.
The old severe statistical admission gate was not modified or overridden.

Both capped methods met the two-percentage-point clean macro-F1 guard at rounds 10
and 15 on all nine clean assignments, on validation and test. Their worst test
losses were **1.31 points** for capped sample and **0.70 points** for capped robust.
Uncapped robust bounded aggregation failed two clean checks on each evaluation
split; its worst test loss was **9.39 points**. Thus the publication's pooled clean
guard failure belongs to the uncapped control, not to the new capped methods.

## What did not pass

Capped robust had greater paired worst-trigger peak harm than uncapped robust
in **6/18** reserved attack comparisons, on both validation and test. All six
were non-IID cases (seeds 6116104 and 6116105, each across three attack modes).
There were **zero strict improvements** over the uncapped robust control in the
predeclared effective raw-control cases. The raw control was effective in 13/18
cases under the inherited 20-point ASR increase / at-most-5-point clean F1 loss
rule. Ineffective controls remain in the tables.

| Method | Worst clean test F1 loss (points) | Worst full-trigger test peak ASR | Worst full-trigger test final ASR |
| --- | ---: | ---: | ---: |
| TPM-only FedAvg | 0.00 | 100.00% | 99.97% |
| Robust bounded | 9.39 | 75.61% | 32.37% |
| Capped sample | 1.31 | 100.00% | 98.66% |
| Capped robust | 0.70 | 99.94% | 97.80% |

Each cell is the worst over its declared set: clean losses use the nine clean
assignments and fixed rounds 10/15; attack maxima use 18 reserved attack histories.
Different cells can refer to different histories. These are worst cases, not
cohort averages. The most severe capped-robust complete-trigger case was non-IID
seed 6116105. A valid coefficient ceiling and good clean-branch accuracy did not
prevent an effective backdoor in this protocol.

The hypotheses and thresholds were not changed after observing the test results.
All unsuccessful outcomes remain published. Passing numerical verification means
the implementation reproduces the recorded experiment; it does not mean the
defense satisfies its security criteria.

## Post-hoc coefficient diagnosis

The separately labelled post-hoc analysis checks all 270 rounds of the 18 attacked
capped-robust histories. In 90 of 180 actively manipulated attack rounds, projection
increased the coefficient share of the declared attacker identities relative to
the same input's normalized robust proposal. At non-IID seed 6116105, complete
trigger, round 1, that share rose from **12.1042% to 21.4724%**. The largest proposal
coefficient belonged to benign client06. Capping it redistributed positive weight
to unsaturated clients, including the attackers.

This measured redistribution is consistent with a mechanism for weaker resistance.
It is not an ASR counterfactual and does not causally attribute every difference
between complete trained histories to one round. A zero proposal or quarantined
mass was not resurrected. The one-third ceiling still held. The diagnosis added
no training, test inference or threshold selection.

## Defaults and scope

The standard optional in-round configuration remains `gated_composite`; M5 does
not auto-bind that optional file. The unified witnessed profile explicitly uses
`tpm_only`. This study also uses `tpm_only` admission for all four aggregation
arms, assuming prerequisite trust passed in software. The new operators alter
aggregation after admission. **No default was changed.**

The study produced no new TPM quote and does not validate a new live or physical
TPM deployment. It reuses Data24 and a pinned historical warm start/scaler;
new assignments are exploratory, not an independent dataset. ToN-IoT and the
manuscript remain deferred. The 110-file manuscript guard and 138 generation-source
locks passed. Old interrupted evidence was preserved before repeating invalid
attempts; no genuine scientific failure was discarded.

The next design must address the security/utility tradeoff explicitly, with a new
clean-only calibration and a newly fixed evaluation protocol. This completed
campaign remains evidence against treating coefficient capping alone as a
validated poisoning defense.

## Evidence

- [Verified campaign report](../../results/gates-probes/revision-capped-final-v1/REPORT.md)
- [Numerical and publication summary](../../results/gates-probes/revision-capped-final-v1/summary.json)
- [Independent publication check](../../results/gates-probes/revision-capped-final-v1/publication-verification.json)
- [All case outcomes](../../results/gates-probes/revision-capped-final-v1/cases.csv)
- [Clean utility checks](../../results/gates-probes/revision-capped-final-v1/clean-utility.csv)
- [Paired security comparisons](../../results/gates-probes/revision-capped-final-v1/security-comparisons.csv)
- [Measured timing observations](../../results/gates-probes/revision-capped-final-v1/costs.csv)
- [Residual model/prediction differences](../../results/gates-probes/revision-capped-final-v1/residuals.csv)
- [Separately labelled post-hoc diagnosis](../../results/gates-probes/revision-capped-final-posthoc-v1/diagnosis.json)
