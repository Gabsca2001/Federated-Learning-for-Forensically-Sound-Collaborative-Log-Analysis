# Verified M5 in-round composite campaign

This sanitized snapshot reports the 30-round clean reference execution in which the
gated TPM/statistical policy controlled the actual weighted FedAvg checkpoint during training.
The source campaign was independently verified before publication. The declared execution
condition is `clean-no-injected-attack`; no Byzantine update was injected in this run.

## Main results

- campaign `campaign-8bd69d1bae4ef971c7359e5f`; 15 clients, 30 rounds, 450 signed contributions;
- selected checkpoint: round 25;
- validation macro-F1: `0.961719`;
- isolated test macro-F1: `0.935467`;
- isolated test accuracy: `0.976504`;
- client-local test macro-F1 mean: `0.938112`;
- 369 fully accepted, 75 downweighted, and
  6 quarantined contributions;
- 444/450 contributions retained nonzero
  weight (`98.67%`);
- clean-run intervention rate: `18.00%`; strict quarantine
  false-positive rate: `1.33%`.

All 450 contributions passed the M4/M5 trust gate. Therefore the 75 downweights and six
quarantines are statistical interventions over clients declared clean by the experiment. They
begin at round 10. This is evidence that the fixed clean
calibration is not invariant to the evolving update geometry; it is not evidence that those
clients were malicious. Five quarantines concern `client06`, and one concerns `client11`.
Cosine-to-median and coordinate-median distance dominate the treated cases.

Every contribution also has an exact decision explanation. It states which trust checks passed,
the score and signed threshold headroom, the leading scalar indicators, the top three named
parameter tensors responsible for update-to-median distance, all four policy outcomes, prior
client interventions, risk rank among the round peers, retained FedAvg weight, and the actual
versus full-weight counterfactual aggregate displacement. The explanation is a deterministic
rule trace; it is not generated prose and does not use the test split.

The benign-only temporal holdout contains 4320 windows and 13
false alerts (`0.30%`). Its six-class macro-F1
must not be interpreted as multiclass performance because five classes have zero support.

## Files

- `summary.json`: compact metrics, source hashes, rates, and indicator saturation counts;
- `rounds.csv`: validation performance, risk, and decision counts for every round;
- `clients.csv`: per-client treatment and selected-checkpoint local-test macro-F1;
- `decisions.csv`: 450 compact policy decisions, threshold margins, dominant drivers, and
  aggregate influence values;
- `explanations.jsonl`: complete structured explanations for all 450 contributions;
- `intervention-explanations.md`: human-readable investigations of all 75 downweights and six
  quarantines;
- `admission-and-validation.png`: validation trajectory and treatment counts;
- `client-treatment.png`: accepted/downweighted/quarantined counts by client;
- `selected-confusion-matrices.png`: row-normalized validation, test, and temporal matrices.

## Interpretation boundary

This clean run measures compatibility cost and false interventions. It does not measure attack
detection because no attacker is present. The high selected-checkpoint scores do not by
themselves prove that the admission policy caused an improvement. A causal robustness claim
requires paired clean/attacked policy ablations under the same initialization and data contract.

Source campaign-manifest SHA-256: `817ca271657b382725333ba30b242c5aba3a2ea653d63c3b1b0a3cbba3424ebf`. Source selected
evaluation SHA-256: `76f9a95d5bcdcde19a3363dd961a9ad52dca8d841efc495c55b1d602d280d6fe`. The decision-set digest in
`summary.json` binds the relative path and SHA-256 of all 450 signed decision artifacts.
