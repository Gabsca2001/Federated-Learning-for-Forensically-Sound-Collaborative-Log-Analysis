# M6-linked M8 verified preservation closure

This snapshot is the compact, Git-trackable view of the final thesis experiment. It closes the
same 30-round campaign used by the M6 trust/statistics disagreement study and the linked M7
investigation. The multi-gigabyte source evidence remains under `artifacts/`; this directory
publishes only sanitized measurements, identifiers, cryptographic bindings, and figures.

## What was verified

The final receipt `m8-in-round-final-verification-67924c5247b31fce59ae5080` was rebuilt from the offline recovery package and
the M8.5 accounting workspace. All 5 assurance stages passed with final
state `merkle-committed-time-anchored-recovery-exported-in-round-campaign-accounted-finally-verified`. The canonical final core is
`67924c5247b31fce59ae508042705a022146c36ada33c8247a451aec787ec6e0` and the published receipt bytes hash to
`78dead06d3e99f91678df7741c2745e09e9d7aea6ace53c4f9532ebd56a73a0d`.

| Stage | Verified result |
|---|---|
| M8.1 inventory | 3,011 payload files and 7 external digest bindings |
| M8.2 commitment | 3,018 leaves; root `1362e47ca27682083b3a116bbd26fc90e80631f1ed87b268984211dcbe4ce2ba` |
| M8.3 time anchor | RFC 3161 at `Sep  9 00:13:49 2026 GMT`; timestamp `m8-timestamp-anchor-1a4cceb5a6de79502f2cf0f2` |
| M8.4 recovery | 3,011 payload + 11 assurance entries; 2.488 GiB TAR |
| M8.5 accounting | 30 rounds × 15 clients = 450 unique submissions reconstructed offline |
| M8.6 final lineage | zero missing contributions; cross-stage identifiers, digests, selected checkpoint, and campaign lineage agree |

## Training-time admission result

Every submitted bundle passed the seven admission checks actually observed by M5, including
active enrollment, TPM ESK signature, and fresh attestation: 3,150/
3,150 checks and 450/
450 trust decisions. Across the deployed gated-composite trajectory:

- 334 contributions were accepted at full weight;
- 24 were accepted at reduced weight;
- 92 were excluded from aggregation;
- 358 therefore contributed non-zero weight, because downweighted
  contributions are contributors rather than quarantines.

Within the controlled 2×2 disagreement design, all 90 unsafe
cells were quarantined and 2 of
360 safe cells were quarantined. This yields unsafe recall
`1.000` and strict safe false-positive rate
`0.0056` for the deployed policy. These labels are
experimental ground truth for the controlled treatments, not claims about malicious intent.

The four policies were evaluated on the same signed submissions. TPM-only and statistics-only
each missed one disagreement direction (30 false negatives each); sequential and
gated-composite detected all 90 unsafe controlled cells. Only gated-composite controlled this
model trajectory. The other three outcomes are paired shadow decisions, which is why they can
be compared without pretending that four independent campaigns were trained.

## Learning and investigation outcomes

Validation-only selection chose round 11. The isolated post-selection
test macro-F1 is `0.924554` with accuracy
`0.960907`. Compared descriptively with the clean reference campaign,
test macro-F1 changed by `-0.010913`. The unweighted
mean of the 15 client-local isolated test macro-F1 values is
`0.932066` with population standard deviation
`0.035769`. These are measurements of
one deterministic campaign, not a multi-seed confidence interval.

The linked M7 chain investigates 16 label-independent test
cases from the same selected checkpoint, resolves 811
events and 826 source records, and preserves verified
Integrated Gradients, prototype geometry, ATT&CK hypotheses, and a human-readable report. Its
15/16
correct-case count is descriptive only; the fixed bundle is not a performance estimate.

## What M8 proves — and what it does not

M8 proves that the retained bytes, inventory, Merkle commitment, trusted timestamp, recovery
package, contribution ledger, selected model, and published experiment identifiers form one
internally consistent chain. It can detect later byte changes and reconstruct the declared
round/client/policy totals without consulting the live M2–M7 workspaces.

It does not prove that every source event is true, that a statistical quarantine identifies a
malicious client, or that the model generalizes outside the evaluated data. All 450 real
`swtpm` appraisals passed. The trust-inadmissible cells used to measure disagreement are
explicit controlled counterfactuals, not observed Quote failures. The timestamp establishes
existence of the root no later than the signed time; legal admissibility and long-term storage
controls remain organizational responsibilities.

## Files intended for thesis analysis

- `summary.json`: compact machine-readable M6→M7→M8 result and interpretation boundaries;
- `thesis-metrics.csv`: one citation-oriented table of the principal observed, controlled,
  post-selection, and verified measurements;
- `policy-outcomes.csv`: paired treatment and confusion counts for all four admission policies;
- `rounds.csv`: per-round contribution, example, attestation, and checkpoint accounting;
- `clients.csv`: per-client submissions, treatments, example counts, and trust refresh counts;
- `stages.csv`: the six assurance stages with identifiers, commitments, and meanings;
- `final-verification-receipt.json`: the canonical final M8.6 receipt;
- `assurance-chain.png`: visual M8 stage chain;
- `intervention-accounting.png`: deployed treatment totals and paired policy recall;
- `manifest.json`: SHA-256 and size of every file in this published snapshot.

Contribution-level decision explanations remain in the M6 result snapshot; prediction-level
explanations remain in the linked M7 snapshot. They are referenced rather than duplicated here.

## Reproduction

After `m8-verify-final-preservation` succeeds, regenerate this public view with:

```bash
python scripts/render_m8_disagreement_preservation_summary.py \
  --recovery-workspace artifacts/m8-recovery-m6-disagreement-local-test-v1 \
  --accounting-workspace artifacts/m8-campaign-accounting-m6-disagreement-local-test-v1 \
  --m6-results results/m6-trust-statistical-disagreement-local-test-v1 \
  --m7-results results/m7-m6-disagreement-investigation-local-test-v1 \
  --output results/m8-m6-disagreement-preservation-local-test-v1
```

The renderer intentionally reruns the offline recovery, accounting, and final-lineage checks
before publishing. Use `--replace-existing-snapshot` only when regenerating the same verified
receipt and only if the existing snapshot still matches its own manifest.
