# Reproducing and inspecting the final correspondence review

This package distinguishes three source releases:

- Historical attested core, 104 package files: fingerprint in
  `obligation-checks.json` / `before-review.json`.
- Before-correction release, 114 files: fingerprint in `before-review.json`.
- Corrected release, 114 files: fingerprint in `source-correction.json` and
  `property-code-evidence-matrix.json`.

The source archive contains the corrected `src/fl_forensics`, the original
104-file `historical-runtime/fl_forensics`, the 114-file before-correction
`current-source/fl_forensics`, the changed regression module, review scripts
and before/after material. Historical campaign payloads and source references
remain at the pinned roots named in the ledger; this archive is not a copy of
the full experimental corpus. Use the original environment/dependencies and
an isolated repository copy for reproduction. Do not overwrite the sealed
review, source cases or signed graphs.

The original execution sequence was:

1. `prepare_review.py` froze the original references, thesis/index, source and
   documentation before review. It authenticated/extracted the historical code.
2. Run the full pre-fix suite (631 passes) and
   `check_historical_obligations.py` with `historical-runtime` as `PYTHONPATH`.
3. The current-release finite checker examined policy, coefficient and prefix
   obligations. Its final version reads the explicit correction metadata;
   pre-fix outputs are retained separately.
4. The replay probe exposed cross-round graph cycles. The borrowed-byte probe
   exposed false numerical/scoring attribution under the before-correction
   release. The graph intake evidence is signed; the numerical fixture backend
   is simulated and does not claim real TPM attestation.
5. `fix_submission_occurrences.py` installed the source/test change and preserved
   pre-fix files. `close_source_correction.py` completed the regression fixture
   and recorded the final source hashes. The authoritative consolidated change
   is `submission-occurrence-fix.patch`.
6. Run the final full suite (633 passes), the campaign module (27 passes), lint
   on the three changed files, and `check_current_obligations.py` with corrected
   `src` on `PYTHONPATH`. Set BLAS/OpenMP/MKL thread counts to one.
7. Run the replay probe under the preserved before-correction package plus
   pre-fix test fixtures. Run the borrowed-byte probe under both before/after
   packages. Outputs include their actual implementation fingerprint.
8. `check_occurrence_scope.py` checks the retained attested graph for this alias
   condition and records a separate corrected source-function index.
9. `build_correspondence.py` binds real functions/lines/hashes and writes the
   conditional proof annex, scope table and thesis handoff.

`finalize_review.py` is preserved for inspection. It checks the precise allowed
source changes, full-suite results, probes, original roots, metadata links and
unchanged thesis/index before creating a signed local analyst completion and
updating maintained status documents. It is not an independent proof checker,
trusted timestamp or external witness service. Reproduction in another workspace
requires recording its own paths, authority and circumstances.

Old signed round/graph snapshots must be verified with their preserved source
release. Their content-keyed identities are not silently migrated to the new
submission-occurrence profile. No original corpus training or TPM campaign was
rerun in this formal review; new training in unit tests is fixture validation.
