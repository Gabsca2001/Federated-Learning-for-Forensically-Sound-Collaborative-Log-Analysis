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

## Evidentiary interpretation

The source boundary is the controlled-ingestion evidence already preserved by
M2. The bundle carries source-record and source-file digests; it does not copy
raw Parquet rows. This establishes a resolvable, digest-valid derivation path
within the implemented experiment. It does not retroactively attest the
historical UWF capture or turn public dataset labels into independently
observed facts.

Prediction confidence is a model-derived measurement. The reference label is
retained only for experimental evaluation and never enters the inference
tensor. Integrated Gradients and prototype distances are separate derived
artifacts; ATT&CK mappings will follow the same separation. All remain
interpretations rather than primary Zeek evidence.

Integrated Gradients describes local model sensitivity along one declared
baseline path; it is not a causal attribution. Prototype distance describes
geometry in the learned M5 embedding; proximity is not proof of class
membership. Neither artifact modifies or replaces the source-event lineage.
