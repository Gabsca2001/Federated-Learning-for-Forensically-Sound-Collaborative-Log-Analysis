# Frozen adaptive attack pilot — observed result

The declared targeted objective was not achieved: reconnaissance-to-benign ASR
remained 0.000, with an absolute gain of
0.000 against the clean control. This is a negative result
for this finite search, not evidence that all adaptive attacks fail.

The search evaluated 64 adaptive proposals and two controls.
60 adaptive proposals retained all three attackers
and the required contributor count. The selected query is 48
(one-based; artifact index 47). Selection followed the predeclared
ASR, then target cross-entropy, then earliest-query rule; it did not maximize F1 loss.
Its pooled validation macro-F1 was 0.937989, versus
0.948184 for the clean aggregate: a decrease of
1.019 percentage points. Admission therefore
does not imply the targeted attack succeeded, and ASR failure does not imply zero damage.

## Interpretation and limits

All optimization feedback comes from the same privileged validation oracle used by
the gate. No test or temporal holdout is accessed. There is one seed and one frozen
round, no independent generalization estimate and no live model trajectory.
Candidate tensors are derived experimental artifacts, not newly TPM-signed updates.
The original signatures remain attached only to the original source submissions.
The fixed sign-flip control failed the feasibility condition.

The figure shows all attempts, including rejected ones. Its vertical dotted line
marks selection; the horizontal dashed line marks the predeclared targeted success
threshold. The loss plot explains the tie-break when ASR stays unchanged.

## Reproduction

Run `python scripts/run_m6_adaptive_frozen.py verify` for byte-for-byte search
recomputation. This report checks inventory and selection consistency; it is not a
substitute for that verifier. `report-manifest.json` binds every input decision,
the experiment summary, reporting code and published files by SHA-256.
The next experiment must separately bind live proposals, adaptive selection and
new client signatures before aggregation, using fresh evidence directories.
