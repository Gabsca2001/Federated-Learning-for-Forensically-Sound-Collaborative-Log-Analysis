# Milestone 7 — Investigation

## Scope and gate order

M7 turns a model output into an investigative artifact without promoting a
model interpretation to primary evidence. Its implementation order is:

1. prediction bundle and complete source-event lineage;
2. Integrated Gradients and prototype-distance explanation bundle;
3. versioned ATT&CK mapping;
4. deterministic report bundle.

A later layer may consume only an artifact that passes the verifier of every
earlier layer. In particular, a prediction cannot enter an explanation or a
report when its checkpoint, window, snapshot, event, or source-record
reference is missing or digest-invalid.

## Prediction Bundle v1

`m7-predict` consumes a verified M5 secure round, the exact M3 partition
workspace copied into that round, and its verified M2 Data24 snapshot. It
forces CPU inference with the frozen classification head. The command accepts
either explicit window identifiers or the first `N` lexicographically ordered
identifiers from one declared evaluation split. The latter selection is
independent of labels, predictions, confidence, and test performance.

The command reconstructs each selected M3 feature row from the M2 window and
training-only scaler. It then resolves the M2 window's event identifiers in
`lineage.jsonl`. Every event must resolve to at least one controlled-ingestion
source reference containing a Parquet path, row number, source-record SHA-256,
and the SHA-256 of the referenced source file. Publication is fail-closed: no
partial bundle is written when one invariant fails.

The immutable output contains three files:

- `predictions.json`: predicted class, confidence, probability margin, logits,
  full class probabilities, inference-input digest, and an evaluation label
  explicitly marked as not used for inference;
- `lineage.json`: normalized prediction-to-window-to-event-to-source-record
  resolution with all intervening artifact digests;
- `manifest.json`: an integer-only canonical core binding the verified M5
  checkpoint, M3/M2 snapshots, selection policy, prediction and lineage
  digests, implementation/configuration digests, and a zero-violation
  reportability gate.

The bundle is content-addressed but not yet externally anchored. Merkle root,
trusted time proof, recovery export, and campaign-level invariant accounting
belong to M8.

`m7-verify-predictions` independently verifies and reconstructs the M5
checkpoint, M3 partitions, M2 artifacts and selected scaled rows. It reruns
model inference, resolves the source lineage again, regenerates all three
files byte-for-byte, and rejects missing, changed, or unexpected files.

## Explanation Bundle v1

`m7-explain` accepts only a Prediction Bundle that passes
`m7-verify-predictions`. It explains every prediction in that immutable
selection; it cannot add, remove, or choose cases after observing an
explanation. All computation runs on the verified M5 global model on CPU.
The original `configs/investigation.yaml` remains byte-identical because its
digest is part of the Prediction Bundle. Explanation parameters live in the
separate, versioned `configs/investigation-explanations.yaml` contract.

Integrated Gradients targets the predicted-class logit. Its baseline is the
coordinate-wise median of all verified M3 training features. A deterministic
trapezoidal path begins at 256 steps and doubles, up to 4096, until the
absolute completeness error is at most 0.001. Each explanation retains the
ordered scaled input/baseline values, signed attribution, absolute rank,
target-logit delta, attribution sum, and completeness delta. Failure to meet
the tolerance prevents publication.

Prototype distances use the same M5 encoder. Each M3 client computes
training-only class centroids with a minimum local support of five; no row
embedding is retained. A class reference is published only with a quorum of
three clients and is formed by coordinate median across eligible client
centroids. The bundle records Euclidean distances to every class, the nearest
and second-nearest references, their margin, the predicted-class rank, global
prototype values, local support metadata, and commitments to every local
prototype computation.

The immutable output contains:

- `integrated-gradients.json`;
- `prototype-reference.json`;
- `prototype-distances.json`;
- `manifest.json`, which binds the verified Prediction Bundle, model,
  partition, configuration, implementations, and all explanation digests.

`m7-verify-explanations` first re-verifies and reconstructs the Prediction
Bundle. It then recreates the training baseline, all client/global prototypes,
Integrated Gradients, and distances byte-for-byte. Missing, changed, or
unexpected files fail verification.

## ATT&CK Mapping Bundle v1

`m7-map-attack` accepts only an Explanation Bundle that passes
`m7-verify-explanations`. The mapping contract is versioned independently in
`configs/investigation-attack.yaml` and freezes MITRE ATT&CK Enterprise v19.2.
Rule selection depends only on the model's predicted class. Reference labels,
dataset ATT&CK annotations, Integrated Gradients, and prototype distances are
explicitly excluded from rule selection.

The current model taxonomy maps `credential_access`, `exfiltration`,
`initial_access`, and `reconnaissance` to candidate ATT&CK tactics. `benign`
is represented as not applicable. `multi_tactic` is deliberately preserved as
`unresolved-multi-tactic`; prototype geometry or feature attribution cannot be
used to force a single tactic. Technique-level claims are disabled in this
version because the available model output does not provide sufficient
evidentiary support for them.

The immutable output contains:

- `attack-mappings.json`, with one versioned investigative hypothesis per
  verified prediction;
- `manifest.json`, binding the verified Explanation and Prediction Bundles,
  ATT&CK configuration and implementation digests, model taxonomy, mapping
  counts, and the reportability gate.

`m7-verify-attack` transitively re-verifies the Explanation and Prediction
Bundles, recomputes every mapping, and compares the complete bundle
byte-for-byte. Unknown model classes, missing mappings, modified artifacts,
and unexpected bundle entries fail closed.

The exercised six-case bundle contains two `candidate-tactic` mappings and
four `unresolved-multi-tactic` mappings, with zero unmapped predictions. Its
verified bundle identifier is
`m7-attack-mapping-bundle-6e6be31f1e3592d5f47286af`.

## Investigation Report Bundle v1

`m7-report` is the terminal reporting layer of M7. It accepts only an ATT&CK
Mapping Bundle that passes `m7-verify-attack`; therefore publication also
depends transitively on successful verification of explanations, predictions,
the M5 checkpoint, M3 evaluation rows, and the M2 controlled-ingestion
lineage.

The report is deterministic and has no dynamic timestamp or other
non-reproducible field. Cases are ordered lexicographically by prediction
identifier. Each case combines the verified case identity, model prediction
and confidence, a bounded Integrated Gradients summary, prototype geometry,
the versioned ATT&CK hypothesis, and the complete source-event lineage needed
to resolve the case back to controlled-ingestion source records and source
files.

Primary-evidence references are constructed through an explicit allowlist.
For each source record the report retains only the relative source path, row
number, source-record SHA-256, source-file SHA-256, and source-file size.
Dataset fields such as `label_binary`, `label_tactic`, and `label_technique`
are not copied. The experimental `reference_label` is likewise excluded.
Tests demonstrate that changing those labels does not change the generated
investigation report.

The bundle contains exactly:

- `investigation-report.json`, the canonical machine-readable investigative
  artifact;
- `report.md`, a deterministic human-readable representation of the same
  cases;
- `manifest.json`, binding the verified upstream bundles, report
  configuration, implementation, both report digests, case counts, evidence
  counts, and the final reportability gate.

`m7-verify-report` first re-runs the complete upstream ATT&CK verification and
then regenerates the JSON report, Markdown report, and manifest. Verification
requires byte-for-byte equality and rejects missing, modified, or unexpected
files.

The exercised six-case report resolves 69 source events and 81 controlled-
ingestion source records. Two cases carry candidate ATT&CK tactics and four
remain unresolved multi-tactic hypotheses. In two of the multi-tactic cases
the nearest prototype is `reconnaissance`; the report nevertheless preserves
the ATT&CK result as `unresolved-multi-tactic`, demonstrating that prototype
geometry cannot override the mapping policy.

The verified report bundle identifier is
`m7-investigation-report-bundle-54cee841904ab35cc2a7eb8e`. Its canonical core
SHA-256 is
`54cee841904ab35cc2a7eb8efafcd3a27aeaee338c6fc8ed3f328207750bbab7`.
The generated artifact digests are:

- `investigation-report.json`:
  `7e8d4f20229bfb268197383829a91265a19fd8b94e3e4b6a72643270b33bb2a9`;
- `report.md`:
  `f43f104e34d8e97d01f9d6f68cffecda7c4d34debf15e0a228a24bdd08c908db`;
- `manifest.json`:
  `3e4d5faa6ff49760692386caae8f91c10b8037dcaaccfbf6644f0e19c618ca5f`.

The verifier returned `verified`, zero errors, `reportable=true`,
`source_attack_verified=true`, and
`verification_recomputed_report=true`. The complete repository test suite
passes with 139 tests.


## Evidentiary interpretation

The source boundary is the controlled-ingestion evidence already preserved by
M2. The bundle carries source-record and source-file digests; it does not copy
raw Parquet rows. This establishes a resolvable, digest-valid derivation path
within the implemented experiment. It does not retroactively attest the
historical UWF capture or turn public dataset labels into independently
observed facts.

Prediction confidence is a model-derived measurement. The reference label is
retained only for experimental evaluation and never enters the inference
tensor.

Prediction confidence is a model-derived measurement. The reference label is
retained only in the Prediction Bundle for experimental evaluation and never
enters inference, ATT&CK rule selection, or the final investigation report.
Integrated Gradients and prototype distances are derived model
interpretations. ATT&CK mappings are investigative hypotheses derived only
from the predicted class under the frozen mapping policy. None of these
artifacts is promoted to primary Zeek evidence.

The final Investigation Report preserves this distinction explicitly:
controlled-ingestion source-record and source-file digest references form the
primary-evidence boundary; predictions and confidence are model-derived
measurements; Integrated Gradients, prototype geometry, and ATT&CK mappings
are derived interpretations. The report does not claim that these model
outputs establish the historical truth of an attack or retrospectively attest
the original UWF capture.

Integrated Gradients describes local model sensitivity along one declared
baseline path; it is not a causal attribution. Prototype distance describes
geometry in the learned M5 embedding; proximity is not proof of class
membership. ATT&CK mapping is a versioned investigative hypothesis rather
than a technique-level forensic conclusion. None of these layers modifies or
replaces the source-event lineage.
