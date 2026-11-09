# Reproducing the baseline audit

The release preserves source fingerprints, the numerical input index, frozen
protocols, timed samples, scripts and an archive of all 114 package files.
Large signed source campaigns remain at their original artifact roots. The
archive alone does not contain their model exports or the Data24 records.

Use an isolated copy of the repository and the pinned artifact roots named in
`protocol-before-audit-and-benchmark.json` and
`secondary-protocol-before-comparison.json`. Keep earlier signed completions
and their output folders available at their recorded project paths for anchor
checks. Resolve original absolute paths consistently when relocating inputs;
record relocation separately instead of rewriting signed source files.

Use the environment/version information in the first protocol. Place this
release's Python scripts in one audit-output folder and include that folder,
`src` and `scripts` in `PYTHONPATH`. The scripts use the repository working
directory and the fixed new artifact name `artifacts/revision-baseline-closure-v1`.
Run a new reproduction in a copy where that new artifact root is absent;
never remove or overwrite the retained signed release.

Execution order:

1. `prepare_audit.py`
2. `consolidate_dba.py`
3. `audit_gradients.py`
4. `run_benchmarks.py`
5. `prepare_secondary.py`
6. `secondary_comparison.py`
7. `run_envelope_benchmarks.py`
8. `write_report.py`

Run measurement jobs sequentially without a competing training/audit workload.
Set `OPENBLAS_NUM_THREADS`, `OMP_NUM_THREADS` and `MKL_NUM_THREADS` to `1`.
The gradient audit also fixes Torch to one thread. Raw timings can vary with
hardware and load; model replay and the declared numerical comparisons are
the reproducibility criteria, not identical latency samples.

`finalize_study.py` is the original release finalizer: it checks previous
signed anchors, unchanged code/thesis/index, all selected manifests, counts
and frozen benchmark sources before creating a new signed completion and
updating maintained status documentation. It is included for inspection;
running it in an altered reproduction requires separately recording those
new circumstances. It is not a reusable independent-witness service.

The original full test suite was not rerun during this report-only step.
Its 631-pass result is retained and its applicability checked by comparing
all package source bytes to the preceding archived release.
