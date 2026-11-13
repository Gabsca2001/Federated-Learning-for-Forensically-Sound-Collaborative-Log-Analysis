# Reproducing the retrospective group study

Use an isolated repository copy with the pinned source artifacts and preceding
signed output releases available. The source archive contains all 114 package
files and the study scripts; it does not include the large Data24/model corpus.
Original absolute source paths must be resolved consistently. Record relocation
instead of rewriting signed source material.

Scripts assume the repository working directory. Include `src`, `scripts` and
the study-script folder in `PYTHONPATH`; set `OPENBLAS_NUM_THREADS`,
`OMP_NUM_THREADS` and `MKL_NUM_THREADS` to `1`. Training also fixes Torch to
one CPU thread and the original deterministic implementation.

The new root is `artifacts/revision-retrospective-group-validation-v1`.
Run in a copy where that root is absent. Do not delete or overwrite a retained
release to make a reproduction run. Partially written training branches are
deliberately rejected instead of silently resumed or overwritten.

Execution order:

1. `prepare_study.py`: check preceding source closures, freeze the protocol,
   authenticate sources and export 24 feature-only ten-round prefixes.
2. `select_groups.py`: fit/calibrate by cohort; close all twelve evaluation
   selections before reading evaluation truth or attack-success outcomes.
3. `prepare_interventions.py`: fix groups, individuals, oracle-labelled benign
   controls and branch jobs before computing effects.
4. `run_interventions.py`: 293 direct removals and 72 genuinely retrained tails.
5. `evaluate_and_verify.py`: re-read payloads, reaggregate all branch steps,
   check local-input commitments and recompute endpoint metrics.
6. Run the four relevant test modules (`test_group_calibration_v2.py`,
   `test_retrospective_groups.py`, `test_remediation_validation.py`,
   `test_retraining_replay.py`) and save `targeted-tests.xml` beside the scripts.
7. `rewind_hard_case.py`: the separately recorded post-hoc follow-up selects
   the largest existing envelope-removal R15 residual, keeps membership fixed
   and trains four complete 15-round histories from W0.
8. `verify_full_rewind.py`: verify all full-rewind payloads and exact histories.
9. `write_report.py`: English report, full test table, labelled pair diagnosis,
   compact effects and PNG/PDF scientific figures.

`finalize_study.py` is the original release finalizer, preserved for inspection.
It binds source versions, all phase protocols, selections, artifact closures,
reports and figures; it also updates maintained status documents. Running it in
another workspace requires recording the new circumstances and authority.
Its signature is a local software analyst statement, not independent witness
registration, trusted time or client TPM evidence.

The complete source populations were evaluated in earlier studies. The present
comparison is explicitly secondary; the full rewind is a labelled mechanistic
follow-up. No thresholds or selected client sets are retuned by those outcomes.
The prior full 631-pass suite remains source-applicable; 31 relevant tests are
rerun here. Experiment training counts exclude small unit-test fixtures.
