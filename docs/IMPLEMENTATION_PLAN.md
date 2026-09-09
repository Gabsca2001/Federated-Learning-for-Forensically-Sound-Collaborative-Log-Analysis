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
| M5 — Secure training | Signed contexts/bundles/decisions, replay rules, isolated training, campaign chain, optional in-round composite gate | Original and composite 30-round campaigns verify; all 450 in-round trust/statistical decisions and weighted checkpoints independently recompute | Complete for the local Docker/`swtpm` profile; clean-policy calibration analysis published |
| M6 — Byzantine analysis | Frozen attacks, robust aggregation, joint trust/statistical admission, live disagreement training, model/prototype sensitivity, reports | Every method receives the same inputs; all 450 live decisions and weighted checkpoints recompute; invalid assumptions fail; reports regenerate | Complete for the controlled local Docker/`swtpm` profiles |
| M7 — Investigation | Predictions, IG/prototype explanations, ATT&CK mapping, deterministic report | Complete digest-valid lineage from report case to controlled source records | Complete for both the original M5 reference and the M6 live-disagreement checkpoint |
| M8 — Preservation | Inventory, Merkle commitment, RFC 3161 time proof, recovery TAR, accounting | Entire chain verified offline; all campaign invariants and final lineage pass | Original and M6-linked reference closures complete |

## Dependency order

```text
M1 artifact rules
 └─> M2 canonical dataset
      └─> M3 partitions and learning
           ├─> M4 identity/attestation
           │    └─> M5 secure campaign
           │         ├─> original M7 investigation chain
           │         └─> M6 robustness experiments
           │              └─> extended M7 investigation chain
           └──────────────────────────┐
                                      └─> M8 preserved closure
```

The completed original M8 package preserves the canonical M2, M3, M4, M5, and six-case M7
chain. A separate completed package closes the extended thesis experiment: it accepts the
signed in-round M6 checkpoint, preserves the 16-case M7 lineage, and reconstructs every
round/client/policy decision from its offline recovery archive. The two closures use distinct
workspaces and identifiers, so neither silently rewrites the other.

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

The opt-in profile binds the clean-calibrated gated-composite policy before local work
starts. For every round it refreshes/validates M4 evidence, creates the signed context, lets
the isolated clients train and TPM-sign their bundles, applies statistical admission before
aggregation, and independently recomputes the resulting weighted checkpoint. Unit and tamper
tests cover downweighting, idempotent replay, exact aggregation, and modified-update failure.
The clean one-round smoke and separate 30-round campaign are complete. The M6 disagreement
profile reuses this runtime gate with a separately bound treatment contract. Its fresh-baseline
one-round calibration smoke and 30-round container execution are also complete and independently
verified.

### M6 — Byzantine-resilience experiments

M6 freezes verified M5 updates before applying declared attacks. FedAvg, coordinate median,
trimmed mean, Multi-Krum, Bulyan, clipping, and prototype defenses are evaluated under their
explicit `n`/`f` assumptions. Machine-readable results, deterministic figures, and verifier
receipts preserve both successful defenses and failure modes.

The joint-admission pilot compares two ablations (`tpm_only`, `statistics_only`) and two
integrated policies (`sequential`, `gated_composite`) on the same round-11 update population.
Clean-only calibration fixes the statistical and composite thresholds before candidate labels
are evaluated. A controlled 2x2 matrix measures both signal-disagreement directions while
retaining the M5 rule that failed trust is a hard veto.

The contribution-explanation bundle then treats each policy outcome and robust-aggregation
treatment as a forensic event. It reports exact threshold margins, ranked indicator
contributions, named tensor deviations, clip scales, coordinate-retention fractions, Krum
ranks, and client selections. Its verifier recreates all 15 explanations and all six traces
from the frozen inputs; attack labels are excluded from explanation generation.

The live disagreement extension assigns one client to each trust/statistics cell before a round
starts. Its anomalous clients sign a directionally sign-flipped and amplified update with their
TPM ESK, while controlled
trust failures remain explicitly separated from the observed passing `swtpm` evidence. The
gated-composite decision controls the actual aggregation and the other three policies are paired
shadow ablations. The completed 30-round execution recomputed 450/450 decisions. The combined
policies detected all 90 controlled unsafe observations; each single-signal ablation missed 30.
The selected round 11 model reached isolated test macro-F1 `0.924554`. Two of 360 safe
contributions were statistically quarantined and 24 were retained at reduced weight.

### M7 — investigation reporting

The original six-case M5 reference resolves 69 events and 81 controlled source records. The
extended thesis run starts from the selected in-round M6 checkpoint and resolves 16
label-independent test cases through prediction, Integrated Gradients, prototype distance,
ATT&CK mapping, and final JSON/Markdown reporting. It binds 811 events and 826 controlled source
records with zero lineage or verification errors. Five mappings are candidate tactics, four are
not applicable, and seven ambiguous multi-tactic cases remain explicitly unresolved. Its public
snapshot is descriptive and deliberately not presented as a performance estimate.

### M8 — preservation closure

M8 inventories 2,381 artifacts and seven external bindings, commits 2,388 leaves under one
Merkle root, obtains a verified RFC 3161 token, writes a deterministic offline recovery TAR,
and reconstructs the 30-round/450-contribution M5 campaign from that package. The final
verifier reports five verified stages and zero errors.

The separate M6-linked closure inventories 3,011 artifacts, commits 3,018 leaves, timestamps
the new root, and exports a 2.49 GiB recovery TAR. Its in-round accounting reconstructs all
450 submissions, 358 contributors, 24 downweights, and 92 quarantines. It binds the observed
450/450 passing M4 admissions, the controlled disagreement contract, the selected round-11
model, and the linked M7 investigation. M8.6 verifies the complete lineage with zero errors.

## Post-M8 work

These tasks can strengthen the thesis or a later production design, but they are not part of
the completed M1–M8 acceptance chain:

- retain the completed M6-linked M8 recovery archive, accounting workspace, final receipt,
  and sanitized thesis-facing result snapshot as the primary experimental closure;
- retain the completed paired five-seed M3 evaluation as the statistical reference;
- retain the verified 13-stage offline M4–M8 overhead receipt as the reference replay result;
- retain the verified three-trial containerized `swtpm`/mTLS/secure-round runtime receipt and
  its sanitized result snapshot as the local runtime reference;
- add a separate multi-host contribution-API experiment before making network-latency or
  failure-recovery claims;
- retain the completed, byte-recomputed UWF-ZeekData22 post-selection evaluation, its separate
  Discovery alignment stress, and their sanitized result snapshot as the external reference;
- retain the verified one-round in-round smoke and the separate 30-round clean campaign; treat
  its 75 downweights and six quarantines as measured clean-run interventions when designing the
  paired policy calibration/attack experiments;
- retain the verified bound live-disagreement smoke and 30-round campaign; add a genuinely
  failed-attestation runtime fixture only as separate future validation;
- retain the completed contribution-decision explanations as the round-11 mechanism reference
  and extend them only when repeated joint-admission experiments add new source scenarios;
- execute the trust workflow with a physical TPM 2.0 node or fleet;
- move evidence into WORM/object-lock storage with retention and access-control policy;
- define production key custody, rotation, revocation distribution, and disaster recovery;
- test multi-host networking, scale, failure recovery, and service isolation;
- assess privacy mechanisms such as secure aggregation or DP-SGD as separate profiles;
- perform independent security review and reproducibility review.

These extensions must receive new experiment identifiers and must not overwrite the preserved
reference workspaces.
