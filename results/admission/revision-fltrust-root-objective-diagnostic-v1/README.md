# Post-hoc clean-only root-objective diagnosis

This separately frozen ablation changes only Adam root loss class weights to
one on the original balanced root draws. All16 clean source contexts and three
draws are evaluated. No new attacked or test predictions are read or generated.
It is exploratory after the preceding FLTrust screen, not independent confirmation.

Although37/48 clean F1 comparisons improve relative to weighted root training,
34/48 still lose more than2 points versus robust,40/48 versus capped, and six
have fewer than ten positive-score contributors. The prospectively fixed clean
continuation condition fails; no new attack stage is opened. See summary.json,
records.json, protocol-before-clean-ablation.json and the parent screen report.
