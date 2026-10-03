# Untargeted adaptive live M6 campaign v1

Prespecified on 2026-09-30 before this campaign. This is a four-arm, single-seed
exploratory follow-up using the already verified IID partition for seed 342593.
It does not reuse or modify any completed campaign, trust identity, lock, or log.
The earlier targeted reconnaissance-to-benign campaign remains a separate result.

## Research question and threat model

Does an adaptive, untargeted model-poisoning objective reduce selected-checkpoint
test macro-F1, and how does its effect differ when the attacker faces the statistical
gate in addition to M4/M5 trust checks?

Three colluding application-level clients (02, 05, 14) retain valid enrolled TPM
identities and sign their modified updates with their enrolled ESKs. Beginning at
round 11, they observe all 15 current proposals and may query the exact validation
split. The gate calibration and behavior are known to the attacker. The attacker
maximizes all-class true-label cross-entropy and selects the feasible proposal with
the lowest validation macro-F1. The fixed, finite query and perturbation budgets
cannot be expanded after observing outcomes.

This is a bounded adaptive model-replacement stress test. It changes the attack
objective from the earlier class-targeted reconnaissance-to-benign objective; it is
not a claim to cover every Byzantine or backdoor attack family.

## Four matched arms

- `gated_clean`: the existing gated-composite admission policy, no attacker.
- `gated_adaptive`: same policy, adaptive attack in rounds 11–30.
- `tpm_clean`: ordinary M5 signed-bundle admission with M4 TPM identity,
  attestation, replay and integrity checks; no statistical update filter; no attacker.
- `tpm_adaptive`: same TPM-only admission path, adaptive attack in rounds 11–30.

Each arm trains 15 clients for 30 rounds on the same seed and partition. The paired
arms must match byte-for-byte through round 10 within each policy. The gated and
TPM-only clean paths may diverge because the statistical gate can intervene on
otherwise valid contributions; that is part of the treatment comparison.

The search uses 66 queries per attacked round: a clean control, a fixed sign-flip
control, and 64 adaptive proposals (16 at each of four fixed radii). Candidates are
projected around the original client updates. Under gated-composite, all three
attacker contributions must pass the existing contributor rule; under TPM-only,
the official M5 verifier still checks every signed submission and valid M4 trust,
while no M6 statistical rule changes its weight. If no feasible adaptive proposal
exists, original submissions are preserved and used unchanged.

The campaign comprises 120 secure rounds and at most 2,640 adaptive-search queries.
All trust checks, coordinator signatures, per-round independent verification and
M5 final campaign verification remain enabled. Fresh TPMs are provisioned in one
new namespace; all earlier namespaces are left untouched.

## Endpoints and analysis

After all four complete 30-round trajectories and every round verifies, M5 selects
each arm's checkpoint using its unchanged validation macro-F1 rule and evaluates
test exactly once per arm. The optimizer never reads test. Primary paired outcomes
are (1) clean selected-checkpoint test macro-F1 minus adaptive selected-checkpoint
test macro-F1 within each policy and (2) TPM-only paired loss minus gated-composite
paired loss. A positive loss means lower test macro-F1 under attack; a positive
difference-of-losses means a larger observed loss under TPM-only.

A 0.01 absolute test macro-F1 loss is the prespecified practical-success threshold
within a policy. It is an exploratory threshold, not a statistical-significance
test. Also report selected rounds, validation histories, admission/downweight counts,
per-class recall and reconnaissance-to-benign ASR as descriptive secondary metrics.
There is one seed and the same dataset has appeared in previous studies; no
population-level or independent multi-seed claim is warranted.

Validation macro-F1 drives candidate optimization, gate decisions and M5 checkpoint
selection. Test outcomes are not used to tune the optimizer, threshold, policy or
campaign. Any failure of lock, signature, TPM boot identity, a partial round or
independent verification stops the campaign; preserve the evidence and investigate
rather than bypassing checks or restarting the fresh-only runner.

## Reproduction

Plan: `configs/m6-adaptive-untargeted-paired-s342593-v1.json`.
The immutable input/code lock is `configs/m6-adaptive-untargeted-paired-s342593-v1.lock.json`.
The runner and verifier are `scripts/run_m6_adaptive_untargeted_paired_v1.py` and
`scripts/verify_m6_adaptive_untargeted_paired_v1.py`. New runtime evidence will be
under `artifacts/m6-adaptive-untargeted-paired-s342593-v1/`; the local ignored log
is `m6-adaptive-untargeted-paired-v1.log`. Existing campaigns are never resumed or
overwritten by this fresh-only runner.
