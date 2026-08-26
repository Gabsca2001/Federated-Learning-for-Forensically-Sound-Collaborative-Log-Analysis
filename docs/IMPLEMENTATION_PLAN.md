# Implementation plan and acceptance gates

## Planning rule

The project is organized as a sequence of executable acceptance gates. A milestone is
complete only when its generator, verifier, negative cases, and reference runtime evidence
agree. Later milestones may add new artifact types, but they must not silently reinterpret or
rewrite an earlier finalized workspace.

The M1–M8 reference implementation is complete. The table below is therefore both a roadmap
and a map of the evidence currently present in the canonical campaign.

| Milestone | Delivered scope | Acceptance gate | State |
|---|---|---|---|
| M0 — Contract | Package, CLI, YAML contracts, schemas, architecture map | Configuration and schemas load; boundaries are explicit | Complete |
| M1 — Evidence | Acquisition, chain, ECDSA, admission, vault, custody, snapshot | Tampering, wrong identity, expiry, conflicts, and raw/snapshot separation fail closed | Complete |
| M2 — Data | Controlled Data24 ingestion, audit, lineage, windows, split, scaler, central MLP | Deterministic rebuild; no split overlap; training-only scaler; metrics bound by digest | Complete |
| M3 — Federation | 15-client IID/non-IID snapshots, Flower path, auditable FedAvg, PROTEAN | Exact partition coverage; round aggregation reproduced; validation-only selection locked | Complete |
| M4 — Trust | Enrollment, AK/ESK separation, mTLS, Quote appraisal, revocation, TPM adapter | 15/15 `swtpm` gate; nonce replay, wrong pair, altered PCR/log, and revocation rejected | Complete for software-TPM profile |
| M5 — Secure training | Signed contexts/bundles/decisions, replay rules, isolated training, campaign chain | Single-round reconstruction plus 30-round/450-contribution campaign verification | Complete |
| M6 — Byzantine analysis | Frozen attacks, robust aggregation, model/prototype sensitivity, reports | Every method receives the same inputs; invalid assumptions fail; reports regenerate | Complete |
| M7 — Investigation | Predictions, IG/prototype explanations, ATT&CK mapping, deterministic report | Complete digest-valid lineage from report case to controlled source records | Complete |
| M8 — Preservation | Inventory, Merkle commitment, RFC 3161 time proof, recovery TAR, accounting | Entire chain verified offline; all campaign invariants and final lineage pass | Complete |

## Dependency order

```text
M1 artifact rules
 └─> M2 canonical dataset
      └─> M3 partitions and learning
           ├─> M4 identity/attestation
           │    └─> M5 secure campaign
           │         ├─> M6 robustness experiments
           │         └─> M7 investigation chain
           └──────────────────────────┐
                                      └─> M8 preserved closure
```

M8 intentionally preserves the canonical M2, M3, M4, M5, and M7 chain. M6 is a controlled
comparative experiment built from M5 inputs and has its own verified artifacts, but it is not
an upstream dependency of the selected M7 report.

## Completed gates

### M1 — forensic artifact semantics

The vertical slice defines canonical manifests, SHA-256 commitments, ECDSA signatures,
identity/attestation-aware admission, idempotency, custody chaining, a content-addressed
vault, and deterministic snapshots. It also establishes the rule that normalized data and
features never overwrite raw evidence.

### M2 — canonical dataset

The completed reference path uses the UWF-ZeekData24 Parquet release. Source bytes are
recorded in a controlled-download manifest; events are consolidated without discarding label
lineage; capture dates remain indivisible across splits; the scaler is fitted on training
only; and the central model's weights and metrics bind the exact dataset and scaler.

The CSV workflow remains a supported earlier profile and must use distinct workspace and
experiment identifiers.

### M3 — clean federation and auditable adaptation

IID and non-IID partition verifiers enforce complete one-client coverage of every training
and validation window while excluding raw-event fields. Every FedAvg round preserves the
actual local updates and can be independently reconstructed. The PROTEAN extension evaluates
its lambda candidates without test access, locks two declared endpoints, and only then
publishes their final test/holdout comparison.

The paired post-M8 evaluation additionally completed five verified IID/non-IID seeds with
disjoint partition retry streams. Its independently recomputed summary reports sample
dispersion, Student-t intervals, pooled results, and client-local FedAvg/local-only comparisons.

### M4 — trust deployment

The protocol, topology, schemas, adverse cases, and 15-`swtpm` Docker campaign are complete.
Each identity uses distinct AK and ESK roles; Quotes bind one-use nonces and independently
replayed PCR expectations; TLS certificates bind the same enrollment. The physical TPM
adapter and preflight exist, but the separate hardware runtime remains future validation.

### M5 — secure round and campaign

The single-round Docker gate admitted 15/15 TPM ESK-signed bundles and reproduced the stored
FedAvg checkpoint. The chained extension completed 30 rounds, admitted 450/450 contributions,
recorded zero quarantines, and passed independent campaign verification. Validation-only
selection chose round 11 before test evaluation.

### M6 — Byzantine-resilience experiments

M6 freezes verified M5 updates before applying declared attacks. FedAvg, coordinate median,
trimmed mean, Multi-Krum, Bulyan, clipping, and prototype defenses are evaluated under their
explicit `n`/`f` assumptions. Machine-readable results, deterministic figures, and verifier
receipts preserve both successful defenses and failure modes.

### M7 — investigation reporting

Six deterministic test cases were resolved through prediction, Integrated Gradients,
prototype distance, ATT&CK mapping, and final JSON/Markdown reporting. The pipeline resolves
69 events and 81 controlled source records with zero lineage invariant failures. Ambiguous
multi-tactic mappings remain explicitly unresolved.

### M8 — preservation closure

M8 inventories 2,381 artifacts and seven external bindings, commits 2,388 leaves under one
Merkle root, obtains a verified RFC 3161 token, writes a deterministic offline recovery TAR,
and reconstructs the 30-round/450-contribution M5 campaign from that package. The final
verifier reports five verified stages and zero errors.

## Post-M8 work

These tasks can strengthen the thesis or a later production design, but they are not part of
the completed M1–M8 acceptance chain:

- repeat only selected M6 attack scenarios whose stochastic choices require additional
  sensitivity evidence, and report the rationale and dispersion;
- evaluate a genuinely external dataset such as UWF-ZeekData22;
- execute the trust workflow with a physical TPM 2.0 node or fleet;
- move evidence into WORM/object-lock storage with retention and access-control policy;
- define production key custody, rotation, revocation distribution, and disaster recovery;
- test multi-host networking, scale, failure recovery, and service isolation;
- assess privacy mechanisms such as secure aggregation or DP-SGD as separate profiles;
- perform independent security review and reproducibility review.

These extensions must receive new experiment identifiers and must not overwrite the preserved
reference workspaces.
