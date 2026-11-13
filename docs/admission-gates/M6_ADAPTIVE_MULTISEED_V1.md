# Adaptive multiseed extension v1 — prespecified 2026-09-29

Seed 341593 is the completed exploratory v4 reference, whose outcomes are already
known. Four new seeds (342593, 343593, 344593, 345593) are fixed before their runs.
Report all five paired differences and clearly distinguish the initial reference
from the four subsequent replicas; do not present this as a fresh confirmatory study.

Each new seed uses its existing verified IID partition and CPU federation config;
only training/partition seeds change. Clean and adaptive arms share the partition,
training configuration, immutable image and single-thread numerical runtime. Both
run 30 rounds, paired round by round, with exact checkpoint equality at rounds 1–10.
The adaptive arm uses the same three clients, target, search algorithm, oracle,
66-query budget, feasibility rule and original gated-composite policy in rounds
11–30. No post-test tuning, new attack objective, budget expansion or early stopping
based on attack success. Failed searches remain failures and all outputs retained.

Primary endpoints: selected-checkpoint pooled test ASR reconnaissance→benign and
macro-F1, paired adaptive-minus-clean differences. Selection is max validation
macro-F1, earliest tie; test only after both full trajectories and verifications.
Describe mean, sample SD and individual differences; rounds and queries are not
independent experimental replicates. Five seeds remain a small sample. Report
validation trajectories, within-state attack effects, attacker/honest admissions
with denominators, computational cost and every execution failure.

New TPMs and distinct workspaces per pair. Official M4 provisioning with local
verified images and --skip-build; existing M5 commands and independent v4 verifier.
Do not restart TPMs, weaken verification or overwrite a partial workspace. Stop at
first error for diagnosis. Existing empty historical Docker trust networks may be
released only after saving inspection and confirming no attached/running containers;
no evidence, containers or volumes are deleted by that step.

The extension adds 240 rounds (eight arms) and 5,280 attack search queries, plus
independent recomputation. It does not include a no-statistical-filter ablation or
a different poisoning strategy; those require separately fixed protocols.
