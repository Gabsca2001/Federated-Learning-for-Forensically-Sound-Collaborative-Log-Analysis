# Publication readiness — reviewed 2026-09-29

## Ready as completed research snapshots

Publish the following reviewed result directories with their generators, configurations,
protocols and tests. Their README files are dated snapshots; the results index now
provides the current cross-experiment status. No result is relabeled retrospectively.

- results/m6-active-policy-pilot-v1
- results/m6-active-policy-multiseed-v1
- results/m6-policy-sensitivity-replay-v1
- results/m6-live-downplus10-v1
- results/m6-adaptive-frozen-pilot-v1
- results/m6-adaptive-live-smoke-v2
- results/m6-adaptive-paired-v4
- results/m6-numeric-runtime-preflight-v1
- results/m6-adaptive-paired-v3-reproducibility-incident

The first policy comparison contains 20 verified campaigns; live sensitivity contains
ten new campaigns. The frozen adaptive pilot, round-1 signed smoke and paired v4
experiment answer different questions and must not be pooled as equivalent trials.
V4 has one seed, 60 verified rounds, selected test ASR 0/669 in both conditions,
and macro-F1 0.924250 clean versus 0.938970 adaptive. This does not prove universal
robustness, policy superiority or that poisoning improves the model.

## Publishable as ongoing experimental work, not completed efficacy results

The four-new-seed extension has a frozen protocol and versioned execution/recovery
code. Publish it explicitly as ongoing. Keep original scripts referenced by source
locks, including failed invocation versions, for provenance; do not advertise them
as working fresh-run entry points. The current supervisor is
scripts/recover_m6_adaptive_multiseed_invocation_v2.py and its live log is
m6-adaptive-multiseed-v1-recovery2.log. All launchers are environment-specific and
fresh-only. The original runner loses its plan argument on direct re-exec; recovery
v1 then exposed a relative-path problem. Recovery v2 invokes the numerical wrapper
with an absolute runner path. These are documented operational limitations, not a
stable public CLI release. Do not edit locked scripts while the campaigns run.

The original seed341593 outcome was known before fixing the extension. Clearly
separate that reference from the four new replicas in future reporting. New M7/M8
closures for these extensions remain outstanding.

## Suggested commit grouping

1. Implementation and tests: timestamp imprint parsing; active sequential policy
   and checkpoint verification; seed-specific M5 federation configuration; associated
   regression tests and configs. Include the fixture update in test_trust_deployment.py.
2. Research evidence: completed snapshots, generators, source-bound protocols and
   historical runners needed to interpret provenance, plus current README/results index.
3. Ongoing adaptive extension: immutable four-seed plans/lock/protocol, current and
   historical invocation scripts, recovery record and explicit ongoing status.

These groups can be reviewed separately; they must remain dependency-complete before
publishing. Do not stage only a report while omitting code/configuration referenced by
its manifest. At the time of the 2026-09-29 publication review no commit, staging, push or`nexternal message had been performed; later commits are recorded in Git history.

## Keep local

Git ignores *.log, artifacts/, data/, checkpoints and .venv. Additional ignore rules
cover root process-lock files, local m8-final-receipt copies, root resume_m6 shell
helpers and results/m6-adaptive-multiseed-preflight-v1 raw Docker inspections. Public
M8 snapshots remain in their existing reviewed results directories. Do not force-add
private keys, TPM state, client updates, model weights, datasets or raw recovery packages.

## Checks and limits of this review

The initial full suite returned 322 passed and one failure: the old temporary-directory
fixture omitted the federation configuration now required by the M5 runner. The fixture
was updated to provide that input without changing its assertions; all eight deployment
and runner tests then passed. The other 322 tests passed in the full run. Two existing
Click/Typer DeprecationWarnings remain. No production source was changed during this
publication review. This records full-run plus targeted-retest evidence, not a claim
that a second full suite was executed.

Run `.venv/bin/python scripts/audit_publication_readiness.py` to inspect candidate file
sizes, private-key markers/token patterns, README links and active-lock consistency.
Pattern scans are useful checks, not a guarantee of absence of every possible secret.
The first scan covered 183 candidate files, about 3.95 MB, with no sensitive-pattern
or oversized-file findings and no active-lock mismatches. Final counts change as this
checklist and audit script are included. Report snapshots and recorded hashes were
not edited by this documentation review.

## Current accurate points for the supervisor update — 2026-09-30

Completed: five-seed adaptive paired evaluation, four-cell frozen objective/filter
ablation, five-seed gated/sequential comparison, replay/live threshold sensitivity,
and decision explanation/preservation for the named earlier M6 disagreement case.
The five paired adaptive seeds all have selected test ASR 0/669 in clean and adaptive
arms; the mean descriptive adaptive-minus-clean test macro-F1 difference is +0.404 pp.
The new frozen untargeted pilot selected a 25.297 pp validation macro-F1 loss under
TPM-only versus 0.675 pp under gated-composite, without accessing test. It suggests
a filter effect for one round and a finite privileged search, not held-out/live
robustness. M8 does not yet preserve the new objective pilot or the later adaptive
extensions. Avoid claims of universal robustness, causal deployment efficacy,
or statistical superiority of the original gated policy.