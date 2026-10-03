# Supervisor update evidence review — 2026-09-29

> **Completion update — 2026-09-30:** all four adaptive extension pairs are verified.
> The [five-seed report](../results/m6-adaptive-multiseed-v1/README.md) includes paired endpoints,
> trajectories and admission counts. Selected test ASR is 0/669 in both arms for every seed.
> The mean adaptive-minus-clean macro-F1 difference is +0.4038 pp across all five
> seeds (+0.1367 pp for the four new seeds). These are descriptive outcomes, not
> proof of universal robustness or beneficial poisoning. Earlier running/pending
> statements below are historical. The original locked protocol is unchanged.


This review maps the supervisor's 2026-08-27 suggestions to verified reports.
It supplements dated snapshots without rewriting their hash-bound README files.
Repository baseline: published commit 899d49c. This review is a subsequent local
change until separately committed and pushed.

## Composite admission and disagreement

The [controlled disagreement campaign](../results/m6-trust-statistical-disagreement-local-test-v1/README.md)
compares four decisions on the same updates; gated-composite is active and the
other three are shadow policies. These are not four independent training trajectories.
Trust-failure cells are counterfactual over observed passing swtpm attestations.

The [active-policy study](../results/m6-active-policy-multiseed-v1/README.md)
independently runs gated-composite and sequential: five seeds, two conditions,
20 campaigns, 600 rounds and 9,000 contribution decisions. Both exclude 450/450
declared-unsafe contributions per policy. Paired macro-F1 intervals include zero;
this establishes neither superiority nor equivalence. Benign interventions differ.
The [replay sensitivity](../results/m6-policy-sensitivity-replay-v1/README.md)
and [live threshold study](../results/m6-live-downplus10-v1/README.md) distinguish
fixed-signal decision changes from actual retraining effects. Original gated-composite
remains a reference design choice, not a demonstrated universally best policy.

## Explaining and preserving admission decisions

The [live explanations](../results/m6-live-contribution-explanations-local-test-v1/README.md)
cover all 450 contributions in the named 30-round campaign. They reconstruct policy
decisions, trust signals, statistical drivers, retained weight, influence and
counterfactuals; they do not establish malicious intent.

The [M7 investigation](../results/m7-m6-disagreement-investigation-local-test-v1/README.md)
and [M8 preservation](../results/m8-m6-disagreement-preservation-local-test-v1/README.md)
close that historical disagreement case. The timestamp, Merkle tree and recovery
package do not automatically cover later policy, sensitivity or adaptive campaigns.

The separate [attestation failure](../results/m6-real-attestation-failure-local-test-v1/README.md)
uses an authentic swtpm Quote with noncompliant measurements. M4 detects the failure
and admission assigns zero contribution weight. This tests software-TPM integration,
not physical hardware assurance. The selected checkpoint precedes the intervention,
so its predictive metrics do not measure the intervention's effect.

## Adaptive attack

The [paired v4 report](../results/m6-adaptive-paired-v4/README.md) verifies one
exploratory seed, 30 rounds per arm, with three colluding clients during rounds
11–30 and 66 search proposals per attacked round. All 60 malicious contributions
are accepted or downweighted (32 and 28 respectively), yet selected-model test ASR
is 0/669 in both arms. Test macro-F1 is 0.924250 clean and 0.938970 adaptive.
Neither general robustness nor a benefit from attacking follows from this single pair.

The [extension protocol](M6_ADAPTIVE_MULTISEED_V1.md) fixes four further seeds.
It is a prespecified extension of an already observed reference, not an entirely
fresh confirmatory study. Report seed-level paired outcomes and failures.
At this review the recovery2 supervisor and first-seed runner are active;
no final extension completion is claimed. Recheck the receipt before sending
an email that describes the extension as ongoing or complete.

## Documentation and publication checks

Run the full tracked-file audit with `python scripts/audit_publication_readiness.py --all`.
Without --all the original changed/untracked-file review remains available.
The audit scans Markdown file-link targets, selected credential markers, large
files and the active multiseed lock. It is not a proof of semantic correctness,
a complete secret scanner, or a network/Markdown-anchor validator.

Historical progress notes remain historical. The adaptive overview now explicitly
points to completed v4 and the ongoing extension; the M5 overview no longer labels
completed sensitivity and first adaptive experiments as wholly future work.
The architecture limits attestation claims to measured state at appraisal time.

Raw logs and generated workspaces remain local. No experiment sources, locked
protocols, result snapshots or active processes are changed by this review.
## Addendum — adaptive objective and filter ablation, 2026-09-30

The four additional M6 adaptive seed pairs have since completed. A separate four-cell, frozen-round validation pilot compares targeted reconnaissance→benign and untargeted all-class degradation under gated-composite and TPM-only. Its selected untargeted candidate loses 0.675 macro-F1 points with the gate and 25.297 points with TPM-only, on the optimizer's validation set. This supports a gate-effect hypothesis for this finite search and source round; it is not a held-out/live result. See [the report](../results/m6-adaptive-objectives-ablation-v1/README.md) and [prespecified protocol](M6_ADAPTIVE_OBJECTIVES_ABLATION_V1.md). A signed multi-round paired replication is the next evidentiary step.


## Follow-up - verified four-seed untargeted campaign, 2026-10-03

The four-seed, four-arm untargeted adaptive M6 extension is now complete and
verified. Its report and plots are in
[the multi-seed results snapshot](../results/m6-adaptive-untargeted-multiseed-v1/README.md);
the detailed interpretation is in
[M6_ADAPTIVE_UNTARGETED_MULTISEED_RESULTS_V1.md](M6_ADAPTIVE_UNTARGETED_MULTISEED_RESULTS_V1.md).
The earlier seed-342593 source report is preserved
[here](../results/m6-adaptive-untargeted-paired-s342593-v1-continuation-v3/README.md).

Across the 80 attacked rounds, the validation-search success criterion was met
in 46 rounds under TPM-only and 5 under gated-composite. The post-attack
clean-minus-adaptive validation gap averaged -0.003407 for gated-composite and
+0.197421 for TPM-only across the four seed-level summaries. This secondary
analysis is descriptive because validation also drives adaptive proposal search
and checkpoint selection.

The selected-checkpoint test losses averaged +0.000552 for gated-composite and
+0.013886 for TPM-only. The latter is dominated by seed 342593: its TPM-only
adaptive checkpoint was selected at round 10, before the attack began, while
the clean checkpoint was selected at round 27. This is consistent with a
training or checkpoint-selection disruption, not a poisoned update in the
selected round-10 model. Seed 343593 also selected its TPM-only adaptive model
at round 10; the selected post-attack TPM-only checkpoints for seeds 344593 and
345593 had losses of +0.000970 and +0.000000.

These are exploratory seed-level observations on the same dataset, not
independent-dataset replications or evidence of statistical significance.
The earlier planned multi-round replication has therefore been completed; no
new adaptive campaign is needed before consolidating the thesis results.
