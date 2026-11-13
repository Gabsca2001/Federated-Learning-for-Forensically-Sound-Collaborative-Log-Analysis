# Signed live adaptive smoke — verified 2026-09-28

The independent verifier passed: three newly TPM-signed adaptive contributions,
all 66 search queries recomputed, and the actual gated aggregate identical to the
selected predicted aggregate. Honest proposals remained byte-identical.

Reconnaissance-to-benign ASR rose from 0 to 1 on the 343 optimization-validation
rows. Validation macro-F1 fell from 0.342901 to 0.107455 (23.545 percentage points).
Selection index 65 (query 66) followed the declared ASR/loss selection rule.

This is an integration smoke at round 1 from the initial model, not a mature-model
attack or a 30-round experiment. The weak clean baseline matters. It cannot be
compared causally with the previous frozen round-11 negative result. Exact
validation and all proposals were visible to the attacker; no independent test
or temporal holdout was accessed. No multi-seed efficacy claim is warranted.
Additional adaptive scripts are coordinator-bound, not added to the historical
TPM PCR baseline. The failed v1 attempt and its artifacts are preserved.

Recheck with `python scripts/verify_m6_adaptive_live_smoke.py`.
The next research step is a predeclared multiround protocol with matched clean
controls, fixed query budget and attack timing, then independent evaluation.
Do not retune the attack after viewing test results.
