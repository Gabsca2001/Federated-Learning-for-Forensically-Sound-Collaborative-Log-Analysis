# Verified real post-training TPM failure

This sanitized thesis snapshot records a 30-round federated campaign in which a real swtpm
PCR change was introduced for `client03` after local training and before aggregation in round
30. An independent verifier confirmed the authentic AK Quote, the signed
`failed_measurement` appraisal, and exclusion from weighted FedAvg.

## Main result

- campaign `campaign-ddb214b41abf0ec02d52992e`; 15 clients, 30 rounds, 450 signed updates;
- `client03` first passed M4, trained, produced an ESK-signed update, then failed a fresh M4
  appraisal after PCR 10 changed;
- only `fresh_attestation` failed; artifact, identity, context, ESK, and tensor checks passed;
- final decision: `trust_quarantined`; statistical scoring was not reached; nominal weight
  473, effective FedAvg weight 0;
- 443/450 contributions retained non-zero weight: 368 full,
  75 downweighted, 6
  statistically quarantined, and one trust-quarantined;
- selected checkpoint: round 25; validation macro-F1
  `0.961719`, isolated test macro-F1
  `0.935467`, test accuracy
  `0.976504`;
- client-local test macro-F1 mean
  `0.938112`
  (population standard deviation
  `0.036917`).

## Paired clean comparison

The clean reference retained 444/450 contributions; this run retained 443/450. The exact
difference is the one trust quarantine for `client03`. Both runs selected round 25, which is
earlier than the active failure in round 30; consequently their selected
validation/test class metrics are identical. This is expected and must not be reported as a
general claim that TPM exclusion has zero utility cost.

Within round 30, the real and clean checkpoints have the same validation macro-F1
`0.900661`, but their loss differs by
`-0.000813667` and their
parameters differ by `0.020355122` L2. The exact within-round full-weight
counterfactual shift for `client03` is
`0.020356380` L2.

The benign-only temporal holdout is reported only as an operational false-alert check. Its
six-class macro-F1 is not a multiclass generalization score because five classes have zero
support.

## Files

- `summary.json`: compact thesis metrics, paired effects, limitations, and source hashes;
- `attestation-decision-chain.json`: sanitized machine-readable M4 → M5/M6 → FedAvg lineage;
- `verification.json`: independent verifier receipt plus publication consistency checks;
- `rounds.csv`: validation and all four treatment counts for every round;
- `decisions.csv`: compact record for all 450 contribution decisions;
- `target-explanation.md`: human-readable forensic explanation of the target decision;
- `attestation-decision-chain.png`: visual sequence from pre-training authorization to zero weight;
- `admission-and-validation.png`: validation and contribution treatments across 30 rounds;
- `paired-clean-effect.png`: paired admission counts and checkpoint parameter divergence;
- `selected-confusion-matrices.png`: row-normalized validation, test, and temporal matrices.

## Scope

This experiment validates enforcement and provenance for one authentic non-conforming Quote.
It uses swtpm, one client, one late round, and one seed. Earlier/repeated failures and
population-level utility effects remain subjects for multi-seed and sensitivity analysis.
The effective runtime attestation refresh cadence was every
3 rounds.

Source campaign-manifest SHA-256: `6f99cba3f6f5194c6f1ad815f6965554f70cfe73b83888b7f581d6d9154e9d97`. The remaining source digests are
listed in `summary.json`, and every published file is bound by `manifest.json`.
