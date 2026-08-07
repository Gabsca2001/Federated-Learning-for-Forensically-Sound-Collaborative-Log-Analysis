# Milestone 3 — federated baseline contract

## Scope

M3 establishes the clean federated reference before trust deployment, malicious
updates, or robust aggregation are introduced. It uses UWF-ZeekData24 only and
does not change any M2 feature, split, scaler, or label decision.

The baseline has 15 logical clients, 100% participation, 30 FedAvg rounds, two
local epochs per round, batch size 128, Adam at learning rate 0.001, and a fixed
seed. The PyTorch network is `25 → 128 → 64 → 32 → 6`, matching the encoder/head
shape used by the centralized M2 baseline while changing the backend from
scikit-learn to PyTorch.

## Partition profiles

The IID profile performs a deterministic stratified round-robin allocation of
each training class. The non-IID profile draws per-class client proportions from
a Dirichlet distribution with `alpha = 0.3`, retries deterministically until each
client has at least 32 training windows, and records the final distribution.
Validation windows are distributed with the same stratified IID policy in both
profiles so that local validation remains comparable.

Every training and validation window appears in exactly one client snapshot.
Client snapshots contain only scaled feature vectors, labels, window IDs and
capture IDs. They do not contain raw CSV rows, normalized Zeek events, source-line
digests, or event-level lineage. The server artifact contains only the complete
scaled validation, development-test, and temporal-holdout feature sets.

## Two execution paths

`fl_forensics.flower_client` and `fl_forensics.flower_server` implement the current
Flower Message API through `ClientApp`, `ServerApp`, `ArrayRecord`, and
`serverapp.strategy.FedAvg`. This is the runtime portability path for later
simulation and deployment.

`fl-forensics m3-train` is the deterministic forensic experiment runner. It calls
the same PyTorch training primitives and Flower's example-weighted FedAvg
aggregation, but executes clients sequentially. This avoids scheduler-dependent
artifact publication and allows each accepted input, update, checkpoint, metric,
and round relation to be committed before the next round.

## Preserved artifacts

Each client/round produces an update object containing the local model state and
an update record linking it to the base global model and frozen client snapshot.
Each round record lists all 15 updates, their example counts, the aggregation
policy, the resulting checkpoint, global evaluation metrics and the previous
round hash. Model and update objects use content-addressed SHA-256 paths.

The verifier checks M2 and partition lineage, direct artifact hashes, update
objects, round order and hash-chain continuity. It then reloads all 15 updates for
every round, recomputes example-weighted FedAvg and requires exact equality with
the preserved global checkpoint.

## Evaluation report

`fl-forensics m3-report` derives a deterministic visual report from the preserved
`metrics.json` and `comparison.json`; it does not repeat training or inference.
Before plotting, it checks both source digests against the M3 run manifest. An
optional M2 centralized workspace is checked in the same way and can be included
in the comparison chart.

The report contains absolute and row-normalized test confusion matrices,
per-class precision/recall/F1, validation macro-F1 and weighted training loss by
round, local-only/FedAvg/centralized comparison, and per-client local-only test
performance. `summary.json` records the input and figure SHA-256 values. The best
validation round is reported only as a diagnostic because M3 preserves the final
round model; the test split is not a model-selection input.

## Interpretation boundary

M3 measures the clean IID/non-IID effect. It does not simulate Byzantine clients,
sign update bundles, enforce round replay protection, use mTLS, or evaluate TPM
quotes. Those properties belong to M4–M6 and must not be inferred from M3 results.
The final-week temporal holdout remains benign-only and is never reported as a
multiclass test.
