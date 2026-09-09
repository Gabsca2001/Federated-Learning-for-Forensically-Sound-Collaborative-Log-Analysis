# Deterministic live M6 decision case studies

These cases are selected by declared rules over the verified explanation payload;
they are not hand-picked after inspecting attack labels or test performance.

## accepted-nearest-quarantine

Selection rule: Highest composite score among full-weight accepted contributions.

- Slot: round 23, `client09`
- Final status: `accepted`
- Trust admissible: `true`
- Statistical risk: `0.547051268`
- Composite score: `0.273525634`
- Full-weight / quarantine thresholds: `0.274897049` / `0.409154703`
- Retained FedAvg weight: `100.00%`
- Actual / full-weight-counterfactual aggregate shift L2: `0.025087196` / `0.000000000`
- Trust remediation required: `false`
- Decision digest: `b98d32da79b39ca3fa88669a36044739738a24bad109acab3b0536020dd99707`

Mechanism explanation:

- The effective trust gate was admissible and all bound M5 trust checks passed.
- The live gated-composite decision was accepted with score 0.273526; full-weight and quarantine thresholds were 0.274897 and 0.409155.
- Leading statistical-risk contributions: coordinate_median_distance=0.200000, cosine_to_median=0.200000, mad_score=0.138742.
- Leading named tensor deviations from the round median: encoder.2.weight=62.164%, encoder.0.weight=23.883%, encoder.4.weight=11.447%.
- The statistical risk ranked 3 of 15 in this round; policy outcomes: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted.
- FedAvg retained 100.00% of nominal weight; actual leave-one-out influence was 0.025087196 L2 and restoring full weight would shift the aggregate by 0.000000000 L2.
- This is an exact score-level threshold counterfactual; it does not prescribe one unique tensor or indicator change.
- This explains the configured training-decision mechanism and update geometry. It does not prove malicious intent and uses neither test data nor attack labels.

## downweighted-nearest-full-weight

Selection rule: Smallest score excess above the full-weight threshold.

- Slot: round 19, `client12`
- Final status: `accepted_downweighted`
- Trust admissible: `true`
- Statistical risk: `0.551712796`
- Composite score: `0.275856398`
- Full-weight / quarantine thresholds: `0.274897049` / `0.409154703`
- Retained FedAvg weight: `50.00%`
- Actual / full-weight-counterfactual aggregate shift L2: `0.014518237` / `0.013256013`
- Trust remediation required: `false`
- Decision digest: `7c6bcddb4f6d524f2178cde7a20f94d6e0135228c11b65d12b0927973a8c7b65`

Mechanism explanation:

- The effective trust gate was admissible and all bound M5 trust checks passed.
- The live gated-composite decision was accepted_downweighted with score 0.275856; full-weight and quarantine thresholds were 0.274897 and 0.409155.
- Leading statistical-risk contributions: coordinate_median_distance=0.200000, cosine_to_median=0.200000, relative_norm=0.086267.
- Leading named tensor deviations from the round median: encoder.2.weight=62.361%, encoder.0.weight=25.628%, encoder.4.weight=9.063%.
- The statistical risk ranked 4 of 15 in this round; policy outcomes: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.
- FedAvg retained 50.00% of nominal weight; actual leave-one-out influence was 0.014518237 L2 and restoring full weight would shift the aggregate by 0.013256013 L2.
- This is an exact score-level threshold counterfactual; it does not prescribe one unique tensor or indicator change.
- This explains the configured training-decision mechanism and update geometry. It does not prove malicious intent and uses neither test data nor attack labels.

## statistical-quarantine-nearest-boundary

Selection rule: Smallest score excess above the quarantine threshold with admissible trust.

- Slot: round 21, `client06`
- Final status: `statistically_quarantined`
- Trust admissible: `true`
- Statistical risk: `0.868784069`
- Composite score: `0.434392034`
- Full-weight / quarantine thresholds: `0.274897049` / `0.409154703`
- Retained FedAvg weight: `0.00%`
- Actual / full-weight-counterfactual aggregate shift L2: `0.000000000` / `0.032339058`
- Trust remediation required: `false`
- Decision digest: `fbebce60ae2574fd667f2efe75ead6bc3f8d6ee564948d32e2857605dc065f7e`

Mechanism explanation:

- The effective trust gate was admissible and all bound M5 trust checks passed.
- The live gated-composite decision was statistically_quarantined with score 0.434392; full-weight and quarantine thresholds were 0.274897 and 0.409155.
- Leading statistical-risk contributions: coordinate_median_distance=0.200000, cosine_to_median=0.200000, mad_score=0.200000.
- Leading named tensor deviations from the round median: encoder.2.weight=60.321%, encoder.0.weight=23.169%, encoder.4.weight=12.861%.
- The statistical risk ranked 3 of 15 in this round; policy outcomes: tpm_only=accepted, statistics_only=statistically_quarantined, sequential=statistically_quarantined, gated_composite=statistically_quarantined.
- FedAvg retained 0.00% of nominal weight; actual leave-one-out influence was 0.000000000 L2 and restoring full weight would shift the aggregate by 0.032339058 L2.
- This is an exact score-level threshold counterfactual; it does not prescribe one unique tensor or indicator change.
- This explains the configured training-decision mechanism and update geometry. It does not prove malicious intent and uses neither test data nor attack labels.

## trust-statistics-disagreement

Selection rule: Lowest statistical risk among hard trust quarantines.

- Slot: round 1, `client03`
- Final status: `trust_quarantined`
- Trust admissible: `false`
- Statistical risk: `0.000000000`
- Composite score: `0.500000000`
- Full-weight / quarantine thresholds: `0.274897049` / `0.409154703`
- Retained FedAvg weight: `0.00%`
- Actual / full-weight-counterfactual aggregate shift L2: `0.000000000` / `0.015266459`
- Trust remediation required: `true`
- Decision digest: `8ca04254599b4848a2b7017a7689c17a16d8a4bb0c1151d16f28a526fdc4f471`

Mechanism explanation:

- The bound disagreement contract made the effective trust signal inadmissible; the preserved observed swtpm appraisal remains separate and passed.
- The live gated-composite decision was trust_quarantined with score 0.500000; full-weight and quarantine thresholds were 0.274897 and 0.409155.
- Leading statistical-risk contributions: coordinate_median_distance=0.000000, cosine_to_median=0.000000, mad_score=0.000000.
- Leading named tensor deviations from the round median: encoder.2.weight=62.842%, encoder.0.weight=20.973%, encoder.4.weight=14.443%.
- The statistical risk ranked 13 of 15 in this round; policy outcomes: tpm_only=trust_quarantined, statistics_only=accepted, sequential=trust_quarantined, gated_composite=trust_quarantined.
- FedAvg retained 0.00% of nominal weight; actual leave-one-out influence was 0.000000000 L2 and restoring full weight would shift the aggregate by 0.015266459 L2.
- The hard trust gate must first receive admissible fresh evidence; no statistical-score reduction can compensate for an inadmissible trust signal.
- This explains the configured training-decision mechanism and update geometry. It does not prove malicious intent and uses neither test data nor attack labels.

## Interpretation boundary

These records explain the configured decision mechanism and the measured update
geometry. They do not prove that a client was malicious.
