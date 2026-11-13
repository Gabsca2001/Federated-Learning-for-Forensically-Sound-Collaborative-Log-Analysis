# Verified forensic explanations of M6 contribution decisions

This sanitized snapshot explains how the verified joint-admission pilot and five aggregation
strategies treated the same 15 frozen round-11 contributions. It explains update-policy
decisions; it is separate from M7, which explains intrusion predictions over log features.

## Joint-admission explanations

The primary hard-gated composite policy produced:

- accepted: `11`;
- accepted with reduced weight: `1`;
- statistically quarantined: `3`;
- trust quarantined: `0`.

Each row in `client-explanations.csv` records the signed distance from the statistical
quarantine threshold, the largest indicator contribution, and the named parameter tensor
responsible for the largest share of squared distance from the population median. Negative
margin means the candidate is beyond the quarantine boundary. Attack labels were not used to
rank indicators, tensors, or clients.

## Robust-aggregation traces

- L2 clipping changed: `client02`, `client05`, `client14`;
- trimmed mean removed every coordinate from: none;
- MultiKrum did not select: `client02`, `client04`, `client05`, `client06`, `client14`;
- Bulyan candidate selection excluded: `client02`, `client04`, `client05`, `client06`, `client13`, `client14`.

These outcomes have different meanings. Clipping rescales a whole update. MultiKrum makes a
client-level selection. Trimmed mean filters independently per coordinate, so most clients can
be partially retained. Bulyan first selects candidates by Krum rank and then makes a separate
coordinate-level choice. Coordinate median has no client-level accepted/rejected set.

`aggregator-treatment.csv` publishes the exact clip scales, retained-coordinate fractions,
Krum ranks, and selection flags. Every trace was checked against the same aggregation
implementation used by M6 and independently recomputed by the bundle verifier.

## Provenance and interpretation boundary

- explanation bundle: `m6-contribution-explanations-42cefe31761ea6a03014804c`;
- manifest SHA-256: `9784eb76ce021e653c2b456992ba2d8a00a5bfd832bad95656f1b8596a530243`;
- source admission SHA-256: `3faa180da370926cd27e9f08503942af376e2ac9769c147edf4251035cf018d1`;
- campaign: `campaign-aa22aafea800a7d59fe308fc`, round `11`;
- source attack scenario: `model_replacement`;
- explanation count: `15`;
- aggregation traces: `6`;
- attack labels used for explanation: `false`.

These are deterministic mechanism explanations, not proof of malicious intent and not primary
Zeek evidence. The attacked update bytes retain the controlled M6 derivation limitation of the
source admission pilot. The result covers one round and one attack configuration.

`summary.json` contains the compact result and source bindings. `manifest.json` binds every
published file. Model updates, checkpoints, full tensor values, attestation payloads, TPM state,
private keys, and source data remain outside Git.
