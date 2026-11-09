# Proposed correction after frozen V4 diagnosis

This is a concrete implementation specification, not an implemented/validated
replacement. Keep V4 and its failures immutable. Develop the next candidate
separately and freeze a new assessment protocol before observing new outcomes.

## Separate contribution utility risk from actor anomaly

Retain validation macro-F1 and per-class degradation as utility evidence. Its
observed drops are real and include rare-class false-positive predictions. Do
not remove that evidence or treat rare classes as unimportant.

Do not allow a benign validation-risk flag alone to become evidence of malicious
identity, or combine it indiscriminately with another client's norm anomaly to
declare a coordinated group. Produce separate outputs for (1) utility risk of a
contribution, (2) anomalous submission behavior and (3) group hypothesis/evidence.
The original formal separation of provenance, influence and semantic assessment
must remain intact; mandatory trust vetoes must keep their existing semantics.

Evaluate continuous weighted validation loss as a complementary utility channel,
with clean-only calibration and model-state coverage. It improves on the
discontinuity of macro-F1 but is not a proven cure: some falsely flagged honest
updates also increase validation loss. Keep classwise macro-F1 for assessment.

## Replace a rigid median with calibrated episode evidence

V4 misses a client whose five modified rounds all exceed the existing threshold
because five unmodified rounds pull the ten-round median below it. A candidate
episode mechanism should measure a bounded number/duration of anomaly episodes,
allowing separated attack rounds. Choose its statistic before assessment, fit
only on clean data and calibrate the complete client/window search at campaign
level. Do not reuse V4's median threshold for a different temporal statistic.

## Preserve coherent evidence within candidate groups

Group edges must identify which anomaly mechanism is shared and what tensor or
temporal observations support it. Mere concurrent threshold exceedance on unlike
channels is insufficient. Retain larger ambiguous candidate sets for investigation
instead of converting them into a permanent exclusion decision or arbitrarily
selecting the known number of attackers. The ten-contributor limit stays fixed.

## Validate the replacement on unseen assignments

The current source cases are development/diagnostic evidence after this analysis.
Compare the next method and frozen V4 on new actual allocation memberships and
different attacker rosters, fixed before outcomes. Retain clean, intermittent,
unrestricted and relative-radius cases, including ineffective attack controls.
Count false benign members both in clean and attacked histories, missed actors,
ambiguous/oversized groups, and actual altered exports versus scheduled roles.

For groups selected by the method, retain individual/joint and benign controls
and full-origin replay with surviving adaptive attackers. Assess parameter
equality with the same-excluded-roster clean reference as well as full/component
ASR and classwise utility. Oracle-known groups remain a separate diagnostic.

The common-parent honest controls used for diagnosis require private simulator
rows. They cannot become a production detector input. Practical state references
must use explicitly available trusted information and clean-only state coverage.
This diagnostic study introduces no automatic exclusion, policy-default change,
thesis edit, new TPM campaign, ToN-IoT acquisition or external witness deployment.
