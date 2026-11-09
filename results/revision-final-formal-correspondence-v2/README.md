# Final formal correspondence closure

The accepted formal core is supported by explicit conditional manual arguments,
current source/verifier bindings and retained evidence. The review also found
and corrected a concrete graph-identity defect. Local training, admission
arithmetic and aggregation algorithms are unchanged. The thesis and historical
corpus/TPM evidence are preserved.

The [property/assumption/code/verifier/evidence matrix](PROPERTY_CODE_EVIDENCE_MATRIX.md)
covers separation, authenticated modification detection, submission and record
coverage, numerical soundness, non-compensation, original Delta/J, separated
influence diagnostics, anchored review, multiround radius, composed verification,
controlled successor replay, matched reference and empirical adapter/group scope.
The JSON ledger binds every named function to real line locations and source
hashes. Universal statements use the [manual current-release annex](CURRENT_RELEASE_PROOF_ANNEX.md)
and the preserved core proof note; finite checks do not replace those arguments.

## Checks completed now

- All **633 tests pass**, zero failures/errors/skips, two existing Typer warnings.
  The initial 631-pass run is preserved separately; it did not cover the defect.
- The current release passes 3,750 real policy boundary cases, 4,650 frozen
  fixed-K metric cases, 3,780 rescored cases and 3,900 ideal removal identities/
  bounds; undefined normalization is checked separately.
- Each of the two newer action adapters passes 16,384 transitions against a
  separately computed oracle and 512 equal-prefix/different-future pairs.
  Exact retry and quorum non-readmission cases are checked.
- The historical 104-file release is loaded separately from its authenticated
  source archive. Its 4,135 shortest typed witnesses on the 1,678-node graph,
  three sealed radius reports and four counterfactual metrics are checked again.
  It is not relabelled as the current 114-file numerical release.

## Clarifications carried into the proof scope

### Concrete implementation defect corrected

The old graph keyed bundle nodes by content hash. Two signed claims for the
same bytes could therefore merge across rounds or client slots, even though
one was correctly rejected by intake. A rejected cross-round replay caused a
cycle; a same-round borrowed-byte claim acquired the other client's scoring and
checkpoint descendants. The latter occurred even though source and graph
verifiers accepted the old representation.

The fix uses **update_bundle:<submission_id>** as occurrence identity and keeps
the bundle hash as its content commitment. Campaign origins and base-to-update
edges use the same identity. Two regression cases cover both scenarios, using
real signatures/intake with a simulated numerical backend. The old-release
counterexamples are retained alongside the successful current-release checks.
See `source-correction.json` and `submission-occurrence-fix.patch`.
The preserved attested graph was checked separately: its 296 submission
occurrences have 296 distinct bundle-origin nodes. The alias defect is absent
there; that observation is not an exhaustive certificate for all old graphs.

### Claims kept distinct

1. The original scalar-weight/gated-policy theorem is not a complete certificate
   for FLAME, coordinatewise robust rules, literal FedGradTrace or newer adapters.
2. The current statistical adapters can abstain while leaving eligible positive
   proposed masses and quorum true. This is not full statistical acceptance or
   the core live path's unscored-zero-mass rule. Live integration needs an explicit
   caller contract; no operational guarantee is added here.
3. Current/peak-retention invariants prove prefix use and current-evidence
   requirements, not accuracy or eventual quarantine. The retained synthetic
   peak-suppression counterexample excludes that stronger conclusion.
4. The history comparator authenticates neither payloads nor the seed/optimizer
   contract on its own. Case verifiers establish those additional antecedents.
   Same-start unmodified equality can preserve an already contaminated base.
5. Reviews use a separate authenticated layer, while runtime BFS has three edge
   types. Fixed-K J is always one after nonempty allowed removal under the explicit
   absence marker; neither fact should be silently reinterpreted in the thesis.
6. The 20 attested round instances are four five-round trajectories. Later
   successful software DBA/reconstruction studies have different profiles and
   stronger empirical outcomes, not retroactive fresh TPM evidence.

These are explicit [refinements and boundaries](REFINEMENTS_AND_BOUNDARIES.md),
not new professor requirements or a proof that every desired stronger claim
holds. Receipt deadline/delivery, independent witness administration, global
artifact completeness, physical TPM and semantic truth remain outside the
demonstrated guarantees. The original proposal and two mail sources are pinned
in `before-review.json`, with original-language reference text preserved.

## Result and next boundary

The graph-construction correction is included in the final reviewed release.
The core arguments remain conditional on the stated hypotheses and verifier composition. The newer
empirical rules retain their narrower proved invariants and measured limitations.
The package is a local software analyst record, not external mathematical
certification. The exact two package-source changes and one regression-test
change are bound in the final closure; all other package files, historical
evidence, thesis sources and Git index are preserved and checked.

The [thesis handoff](THESIS_HANDOFF.md) specifies the later text changes, including
model indexing, source profiles, negative results and an accurate assistance
disclosure. Before live automatic-policy claims, adaptive and live-TPM integration
work remains. ToN-IoT stays deferred. No thesis text is changed in this step.
