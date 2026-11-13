# Verified joint TPM/statistical admission pilot

This sanitized snapshot compares four contribution-admission policies over the same verified
round-11 M4/M5 identities and M6 model-replacement population. Scores and thresholds were
calculated without candidate attack labels; labels were used only for the evaluation below.

## Observed candidate population

The candidate set contains 15 clients, including
3 controlled anomalous updates. All observed M4/M5 trust signals
passed, so this population measures the `trust-valid / statistically-anomalous` disagreement.
The clean-calibrated statistical threshold is
`0.818309` and the gated-composite quarantine threshold
is `0.409155`.

| Policy | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: |
| TPM only | 0 | 0 | 12 | 3 |
| Statistics only | 3 | 0 | 12 | 0 |
| Sequential | 3 | 0 | 12 | 0 |
| Gated composite | 3 | 0 | 12 | 0 |

TPM-only accepts all three controlled anomalous updates. The other three policies quarantine
them with no benign quarantine in this fixed pilot. Gated-composite also marks one benign
candidate as `accepted_downweighted`; it still contributes and is therefore not counted as a
positive/quarantine in the table.

## Controlled disagreement matrix

The 2x2 matrix reuses one verified normal update and one verified attacked update. Each is
evaluated once with its observed passed trust signal and once with an explicit counterfactual
`fresh_attestation` failure. Counterfactual cells are policy-evaluation controls and were never
admitted by M5.

| Policy | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: |
| TPM only | 2 | 0 | 1 | 1 |
| Statistics only | 2 | 0 | 1 | 1 |
| Sequential | 3 | 0 | 1 | 0 |
| Gated composite | 3 | 0 | 1 | 0 |

TPM-only misses the trust-valid anomalous update; statistics-only misses the trust-invalid
normal-looking update. Sequential and hard-gated composite catch all three unsafe cells and
retain the single safe cell in this controlled matrix.

## Provenance and limitations

- source `admission.json` SHA-256: `3faa180da370926cd27e9f08503942af376e2ac9769c147edf4251035cf018d1`;
- source campaign: `campaign-aa22aafea800a7d59fe308fc`, round `11`;
- attack: `model_replacement`;
- evaluation labels used for scoring: `false`;
- the full source artifact was independently recomputed with
  `m6-verify-joint-admission` before publication;
- attacked candidate bytes are controlled M6 derivations, not newly signed M5 submissions;
- failed-trust cells are declared counterfactual controls, not observed admissions;
- this single round/attack is a mechanism demonstration, not a population-level estimate.

`summary.json` contains the compact policy results and source binding. `clients.csv` exposes
only generic client IDs, risk values, binding semantics, and decisions.
`controlled-disagreement.csv` contains the four policy-control cells. Private keys, TPM state,
attestation payloads, model updates, checkpoints, and source data remain outside Git.
