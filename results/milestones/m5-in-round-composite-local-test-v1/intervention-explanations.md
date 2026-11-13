# Human-readable in-round contribution explanations

These deterministic explanations are derived from signed M5 decisions and the
digest-bound update tensors. They use no test rows or attack labels. Each explanation
describes a policy decision, not proof of malicious intent.

## Quarantined contributions

### Round 14 · client06 · statistically_quarantined

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was quarantined with zero aggregation weight. Its gated-composite score was 0.417631; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.334578, reference=0.199281, robust-z=5.283, risk contribution=0.200; cosine_to_median raw=0.512126, reference=0.905212, robust-z=21.189, risk contribution=0.200; mad_score raw=1.383544, reference=0.935273, robust-z=4.671, risk contribution=0.200.

The client model macro-F1 was 0.060035 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=statistically_quarantined, sequential=statistically_quarantined, gated_composite=statistically_quarantined.

The leading tensor drivers were: encoder.2.weight (61.7% of squared update-to-median distance); encoder.0.weight (24.3% of squared update-to-median distance); encoder.4.weight (11.3% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 4 downweights and 0 quarantines. The actual retained-weight fraction was 0.00.

Its admitted influence on the effective aggregate was 0.000000 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.026619.

Holding trust, peers, and calibration fixed, a composite reduction of 0.008477 would restore non-zero weight and a reduction of 0.142734 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.016954 and 0.285469. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 17 · client06 · statistically_quarantined

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was quarantined with zero aggregation weight. Its gated-composite score was 0.440838; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.361177, reference=0.199281, robust-z=6.322, risk contribution=0.200; cosine_to_median raw=0.371675, reference=0.905212, robust-z=28.760, risk contribution=0.200; mad_score raw=1.587408, reference=0.935273, robust-z=6.796, risk contribution=0.200.

The client model macro-F1 was 0.031935 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=statistically_quarantined, sequential=statistically_quarantined, gated_composite=statistically_quarantined.

The leading tensor drivers were: encoder.2.weight (61.0% of squared update-to-median distance); encoder.0.weight (22.7% of squared update-to-median distance); encoder.4.weight (12.9% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 5 downweights and 1 quarantines. The actual retained-weight fraction was 0.00.

Its admitted influence on the effective aggregate was 0.000000 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.026864.

Holding trust, peers, and calibration fixed, a composite reduction of 0.031683 would restore non-zero weight and a reduction of 0.165941 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.063366 and 0.331881. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 21 · client06 · statistically_quarantined

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was quarantined with zero aggregation weight. Its gated-composite score was 0.500000; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.376280, reference=0.199281, robust-z=6.912, risk contribution=0.200; cosine_to_median raw=0.319560, reference=0.905212, robust-z=31.569, risk contribution=0.200; mad_score raw=1.582598, reference=0.935273, robust-z=6.745, risk contribution=0.200.

The client model macro-F1 was 0.073195 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=statistically_quarantined, sequential=statistically_quarantined, gated_composite=statistically_quarantined.

The leading tensor drivers were: encoder.2.weight (60.3% of squared update-to-median distance); encoder.0.weight (23.2% of squared update-to-median distance); encoder.4.weight (12.9% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 7 downweights and 2 quarantines. The actual retained-weight fraction was 0.00.

Its admitted influence on the effective aggregate was 0.000000 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.032558.

Holding trust, peers, and calibration fixed, a composite reduction of 0.090845 would restore non-zero weight and a reduction of 0.225103 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.181691 and 0.450206. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 22 · client11 · statistically_quarantined

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was quarantined with zero aggregation weight. Its gated-composite score was 0.410590; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.328139, reference=0.199281, robust-z=5.032, risk contribution=0.200; cosine_to_median raw=0.521685, reference=0.905212, robust-z=20.674, risk contribution=0.200; relative_norm raw=1.216045, reference=1.000000, robust-z=2.945, risk contribution=0.196.

The client model macro-F1 was 0.007635 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=statistically_quarantined, sequential=statistically_quarantined, gated_composite=statistically_quarantined.

The leading tensor drivers were: encoder.2.weight (63.0% of squared update-to-median distance); encoder.0.weight (25.4% of squared update-to-median distance); encoder.4.weight (9.8% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 3 downweights and 0 quarantines. The actual retained-weight fraction was 0.00.

Its admitted influence on the effective aggregate was 0.000000 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.023344.

Holding trust, peers, and calibration fixed, a composite reduction of 0.001435 would restore non-zero weight and a reduction of 0.135692 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.002870 and 0.271385. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 25 · client06 · statistically_quarantined

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was quarantined with zero aggregation weight. Its gated-composite score was 0.412907; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.369929, reference=0.199281, robust-z=6.664, risk contribution=0.200; cosine_to_median raw=0.340416, reference=0.905212, robust-z=30.445, risk contribution=0.200; mad_score raw=1.293525, reference=0.935273, robust-z=3.733, risk contribution=0.200.

The client model macro-F1 was 0.000072 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=statistically_quarantined, sequential=statistically_quarantined, gated_composite=statistically_quarantined.

The leading tensor drivers were: encoder.2.weight (61.7% of squared update-to-median distance); encoder.0.weight (18.6% of squared update-to-median distance); encoder.4.weight (15.7% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 9 downweights and 3 quarantines. The actual retained-weight fraction was 0.00.

Its admitted influence on the effective aggregate was 0.000000 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.029210.

Holding trust, peers, and calibration fixed, a composite reduction of 0.003752 would restore non-zero weight and a reduction of 0.138010 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.007504 and 0.276019. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 26 · client06 · statistically_quarantined

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was quarantined with zero aggregation weight. Its gated-composite score was 0.500000; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.343747, reference=0.199281, robust-z=5.641, risk contribution=0.200; cosine_to_median raw=0.402370, reference=0.905212, robust-z=27.105, risk contribution=0.200; mad_score raw=1.305011, reference=0.935273, robust-z=3.853, risk contribution=0.200.

The client model macro-F1 was 0.060822 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=statistically_quarantined, sequential=statistically_quarantined, gated_composite=statistically_quarantined.

The leading tensor drivers were: encoder.2.weight (62.4% of squared update-to-median distance); encoder.0.weight (18.4% of squared update-to-median distance); encoder.4.weight (15.0% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 9 downweights and 4 quarantines. The actual retained-weight fraction was 0.00.

Its admitted influence on the effective aggregate was 0.000000 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.030073.

Holding trust, peers, and calibration fixed, a composite reduction of 0.090845 would restore non-zero weight and a reduction of 0.225103 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.181691 and 0.450206. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

## Downweighted contributions

### Round 10 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.338615; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.272745, reference=0.199281, robust-z=2.869, risk contribution=0.191; cosine_to_median raw=0.852631, reference=0.905212, robust-z=2.834, risk contribution=0.189; validation_impact raw=0.049030, reference=-0.008008, robust-z=2.783, risk contribution=0.186.

The client model macro-F1 was 0.049030 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (67.0% of squared update-to-median distance); encoder.0.weight (17.4% of squared update-to-median distance); encoder.4.weight (13.7% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 0 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010063 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.009369.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.063718 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.127436. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 10 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.290821; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: validation_impact raw=0.056550, reference=-0.008008, robust-z=3.150, risk contribution=0.200; coordinate_median_distance raw=0.264770, reference=0.199281, robust-z=2.557, risk contribution=0.170; cosine_to_median raw=0.868842, reference=0.905212, robust-z=1.961, risk contribution=0.131.

The client model macro-F1 was 0.056550 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.8% of squared update-to-median distance); encoder.0.weight (25.5% of squared update-to-median distance); encoder.4.weight (10.5% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 0 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.009734 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.009062.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.015924 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.031849. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 11 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.378789; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.283489, reference=0.199281, robust-z=3.288, risk contribution=0.200; cosine_to_median raw=0.771699, reference=0.905212, robust-z=7.197, risk contribution=0.200; validation_impact raw=0.055805, reference=-0.008008, robust-z=3.114, risk contribution=0.200.

The client model macro-F1 was 0.055805 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.0% of squared update-to-median distance); encoder.0.weight (18.2% of squared update-to-median distance); encoder.4.weight (15.6% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 1 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010362 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.009648.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.103892 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.207784. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 11 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.319661; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: validation_impact raw=0.054043, reference=-0.008008, robust-z=3.028, risk contribution=0.200; cosine_to_median raw=0.849947, reference=0.905212, robust-z=2.979, risk contribution=0.199; coordinate_median_distance raw=0.251309, reference=0.199281, robust-z=2.032, risk contribution=0.135.

The client model macro-F1 was 0.054043 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (59.7% of squared update-to-median distance); encoder.0.weight (31.7% of squared update-to-median distance); encoder.4.weight (7.0% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 1 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.009347 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.008702.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.044764 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.089527. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 12 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.400000; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.304113, reference=0.199281, robust-z=4.094, risk contribution=0.200; cosine_to_median raw=0.681176, reference=0.905212, robust-z=12.077, risk contribution=0.200; mad_score raw=1.308391, reference=0.935273, robust-z=3.888, risk contribution=0.200.

The client model macro-F1 was 0.060190 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (67.4% of squared update-to-median distance); encoder.0.weight (17.5% of squared update-to-median distance); encoder.4.weight (12.7% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 2 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.011169 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010399.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.125103 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.250206. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 12 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.371476; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.840170, reference=0.905212, robust-z=3.506, risk contribution=0.200; validation_impact raw=0.065882, reference=-0.008008, robust-z=3.605, risk contribution=0.200; coordinate_median_distance raw=0.251359, reference=0.199281, robust-z=2.034, risk contribution=0.136.

The client model macro-F1 was 0.065882 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.4% of squared update-to-median distance); encoder.0.weight (27.6% of squared update-to-median distance); encoder.4.weight (6.7% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 2 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.009355 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.008710.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.096579 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.193158. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 13 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.348884; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.672034, reference=0.905212, robust-z=12.569, risk contribution=0.200; validation_impact raw=0.055161, reference=-0.008008, robust-z=3.082, risk contribution=0.200; coordinate_median_distance raw=0.266515, reference=0.199281, robust-z=2.625, risk contribution=0.175.

The client model macro-F1 was 0.055161 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (61.0% of squared update-to-median distance); encoder.0.weight (23.7% of squared update-to-median distance); encoder.4.weight (12.0% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 3 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010653 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.009864.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.073987 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.147973. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 13 · client11 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.315365; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: validation_impact raw=0.062964, reference=-0.008008, robust-z=3.463, risk contribution=0.200; cosine_to_median raw=0.852522, reference=0.905212, robust-z=2.840, risk contribution=0.189; relative_norm raw=1.136082, reference=1.000000, robust-z=1.855, risk contribution=0.124.

The client model macro-F1 was 0.062964 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (61.0% of squared update-to-median distance); encoder.0.weight (29.3% of squared update-to-median distance); encoder.4.weight (7.9% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 0 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.009177 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.008497.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.040468 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.080937. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 13 · client12 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.354258; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.817122, reference=0.905212, robust-z=4.748, risk contribution=0.200; relative_norm raw=1.196996, reference=1.000000, robust-z=2.686, risk contribution=0.179; coordinate_median_distance raw=0.263760, reference=0.199281, robust-z=2.518, risk contribution=0.168.

The client model macro-F1 was 0.007276 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.5% of squared update-to-median distance); encoder.0.weight (25.3% of squared update-to-median distance); encoder.4.weight (8.2% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 0 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010513 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.009734.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.079361 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.158722. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 13 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.377314; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.749300, reference=0.905212, robust-z=8.404, risk contribution=0.200; validation_impact raw=0.065160, reference=-0.008008, robust-z=3.570, risk contribution=0.200; coordinate_median_distance raw=0.268578, reference=0.199281, robust-z=2.706, risk contribution=0.180.

The client model macro-F1 was 0.065160 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (63.5% of squared update-to-median distance); encoder.0.weight (27.1% of squared update-to-median distance); encoder.4.weight (7.5% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 3 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010741 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.009946.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.102417 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.204834. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 14 · client01 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.296708; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.791767, reference=0.905212, robust-z=6.115, risk contribution=0.200; validation_impact raw=0.057708, reference=-0.008008, robust-z=3.207, risk contribution=0.200; coordinate_median_distance raw=0.234246, reference=0.199281, robust-z=1.365, risk contribution=0.091.

The client model macro-F1 was 0.057708 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (67.7% of squared update-to-median distance); encoder.0.weight (20.1% of squared update-to-median distance); encoder.4.weight (10.1% of squared update-to-median distance).

Its statistical risk ranked 5 of 15 in this round (rank 1 is highest). Before this round the client had 0 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010143 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.009330.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.021811 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.043622. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 14 · client04 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.325371; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.285446, reference=0.199281, robust-z=3.365, risk contribution=0.200; cosine_to_median raw=0.703212, reference=0.905212, robust-z=10.889, risk contribution=0.200; mad_score raw=1.138435, reference=0.935273, robust-z=2.117, risk contribution=0.141.

The client model macro-F1 was 0.006703 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.3% of squared update-to-median distance); encoder.0.weight (25.7% of squared update-to-median distance); encoder.4.weight (9.1% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 0 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012364 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011375.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.050474 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.100948. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 14 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.348928; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.720464, reference=0.905212, robust-z=9.959, risk contribution=0.200; validation_impact raw=0.063809, reference=-0.008008, robust-z=3.504, risk contribution=0.200; coordinate_median_distance raw=0.269089, reference=0.199281, robust-z=2.726, risk contribution=0.182.

The client model macro-F1 was 0.063809 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (65.8% of squared update-to-median distance); encoder.0.weight (24.5% of squared update-to-median distance); encoder.4.weight (7.6% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 4 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.011983 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011025.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.074031 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.148062. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 14 · client15 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.304442; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.830292, reference=0.905212, robust-z=4.039, risk contribution=0.200; validation_impact raw=0.065580, reference=-0.008008, robust-z=3.591, risk contribution=0.200; relative_norm raw=1.104444, reference=1.000000, robust-z=1.424, risk contribution=0.095.

The client model macro-F1 was 0.065580 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (66.6% of squared update-to-median distance); encoder.0.weight (20.8% of squared update-to-median distance); encoder.4.weight (10.7% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 0 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010036 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.009234.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.029544 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.059089. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 15 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.289036; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.287139, reference=0.199281, robust-z=3.431, risk contribution=0.200; cosine_to_median raw=0.609430, reference=0.905212, robust-z=15.944, risk contribution=0.200; mad_score raw=1.138735, reference=0.935273, robust-z=2.120, risk contribution=0.141.

The client model macro-F1 was 0.073479 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.9% of squared update-to-median distance); encoder.0.weight (27.5% of squared update-to-median distance); encoder.4.weight (7.7% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 0 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.011052 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010263.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.014139 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.028278. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 15 · client04 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.291468; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.292553, reference=0.199281, robust-z=3.642, risk contribution=0.200; cosine_to_median raw=0.592730, reference=0.905212, robust-z=16.844, risk contribution=0.200; mad_score raw=1.145252, reference=0.935273, robust-z=2.188, risk contribution=0.146.

The client model macro-F1 was 0.066522 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.4% of squared update-to-median distance); encoder.0.weight (27.3% of squared update-to-median distance); encoder.4.weight (8.1% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 1 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.011152 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010355.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.016571 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.033142. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 15 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.287000; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.667737, reference=0.905212, robust-z=12.801, risk contribution=0.200; coordinate_median_distance raw=0.275238, reference=0.199281, robust-z=2.966, risk contribution=0.198; mad_score raw=1.052114, reference=0.935273, robust-z=1.218, risk contribution=0.081.

The client model macro-F1 was 0.001338 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (65.1% of squared update-to-median distance); encoder.0.weight (24.0% of squared update-to-median distance); encoder.4.weight (8.6% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 5 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010450 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.009704.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.012103 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.024205. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 16 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.289212; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.310638, reference=0.199281, robust-z=4.348, risk contribution=0.200; cosine_to_median raw=0.594211, reference=0.905212, robust-z=16.764, risk contribution=0.200; relative_norm raw=1.122881, reference=1.000000, robust-z=1.675, risk contribution=0.112.

The client model macro-F1 was 0.070203 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (65.5% of squared update-to-median distance); encoder.0.weight (24.5% of squared update-to-median distance); encoder.4.weight (8.3% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 1 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012558 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011628.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.014315 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.028631. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 16 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.396410; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.381576, reference=0.199281, robust-z=7.118, risk contribution=0.200; cosine_to_median raw=0.391587, reference=0.905212, robust-z=27.687, risk contribution=0.200; mad_score raw=1.404318, reference=0.935273, robust-z=4.888, risk contribution=0.200.

The client model macro-F1 was 0.003485 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (61.6% of squared update-to-median distance); encoder.0.weight (21.1% of squared update-to-median distance); encoder.4.weight (14.3% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 4 downweights and 1 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.015032 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.013919.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.121513 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.243026. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 16 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.289147; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.298895, reference=0.199281, robust-z=3.890, risk contribution=0.200; cosine_to_median raw=0.580256, reference=0.905212, robust-z=17.517, risk contribution=0.200; mad_score raw=1.083838, reference=0.935273, robust-z=1.548, risk contribution=0.103.

The client model macro-F1 was 0.001617 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.2% of squared update-to-median distance); encoder.0.weight (24.5% of squared update-to-median distance); encoder.4.weight (8.4% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 6 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.011734 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010865.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.014250 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.028500. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 16 · client15 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.337925; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.277398, reference=0.199281, robust-z=3.050, risk contribution=0.200; cosine_to_median raw=0.744301, reference=0.905212, robust-z=8.674, risk contribution=0.200; relative_norm raw=1.190041, reference=1.000000, robust-z=2.591, risk contribution=0.173.

The client model macro-F1 was 0.009873 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (66.4% of squared update-to-median distance); encoder.0.weight (19.6% of squared update-to-median distance); encoder.4.weight (11.8% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 1 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.011070 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010251.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.063028 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.126055. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 17 · client04 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.365722; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.320656, reference=0.199281, robust-z=4.740, risk contribution=0.200; cosine_to_median raw=0.508353, reference=0.905212, robust-z=21.392, risk contribution=0.200; mad_score raw=1.233507, reference=0.935273, robust-z=3.108, risk contribution=0.200.

The client model macro-F1 was 0.036274 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.0% of squared update-to-median distance); encoder.0.weight (25.2% of squared update-to-median distance); encoder.4.weight (8.1% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 2 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012576 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011645.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.090825 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.181650. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 17 · client11 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.332016; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.700222, reference=0.905212, robust-z=11.050, risk contribution=0.200; coordinate_median_distance raw=0.261442, reference=0.199281, robust-z=2.427, risk contribution=0.162; validation_impact raw=0.033741, reference=-0.008008, robust-z=2.037, risk contribution=0.136.

The client model macro-F1 was 0.033741 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.1% of squared update-to-median distance); encoder.0.weight (27.7% of squared update-to-median distance); encoder.4.weight (6.6% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 1 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010528 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.009748.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.057119 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.114238. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 18 · client09 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.358878; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.367398, reference=0.199281, robust-z=6.565, risk contribution=0.200; cosine_to_median raw=0.341978, reference=0.905212, robust-z=30.361, risk contribution=0.200; mad_score raw=1.637752, reference=0.935273, robust-z=7.320, risk contribution=0.200.

The client model macro-F1 was 0.045900 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (61.9% of squared update-to-median distance); encoder.0.weight (21.6% of squared update-to-median distance); encoder.4.weight (14.3% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 0 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013402 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012477.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.083981 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.167963. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 18 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.356740; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.339755, reference=0.199281, robust-z=5.485, risk contribution=0.200; cosine_to_median raw=0.426862, reference=0.905212, robust-z=25.785, risk contribution=0.200; mad_score raw=1.220128, reference=0.935273, robust-z=2.968, risk contribution=0.198.

The client model macro-F1 was 0.001384 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.6% of squared update-to-median distance); encoder.0.weight (18.7% of squared update-to-median distance); encoder.4.weight (15.4% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 7 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012263 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011418.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.081843 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.163686. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 19 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.352056; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.348135, reference=0.199281, robust-z=5.813, risk contribution=0.200; cosine_to_median raw=0.362463, reference=0.905212, robust-z=29.256, risk contribution=0.200; mad_score raw=1.257117, reference=0.935273, robust-z=3.354, risk contribution=0.200.

The client model macro-F1 was 0.067550 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.3% of squared update-to-median distance); encoder.0.weight (24.7% of squared update-to-median distance); encoder.4.weight (9.1% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 2 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013480 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012482.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.077159 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.154317. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 19 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.369019; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.342616, reference=0.199281, robust-z=5.597, risk contribution=0.200; cosine_to_median raw=0.407477, reference=0.905212, robust-z=26.830, risk contribution=0.200; mad_score raw=1.298152, reference=0.935273, robust-z=3.781, risk contribution=0.200.

The client model macro-F1 was 0.002903 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (60.6% of squared update-to-median distance); encoder.0.weight (20.5% of squared update-to-median distance); encoder.4.weight (15.9% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 5 downweights and 2 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013776 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012756.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.094122 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.188243. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 19 · client12 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.343372; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.308164, reference=0.199281, robust-z=4.252, risk contribution=0.200; cosine_to_median raw=0.542590, reference=0.905212, robust-z=19.547, risk contribution=0.200; mad_score raw=1.141807, reference=0.935273, robust-z=2.152, risk contribution=0.143.

The client model macro-F1 was 0.000452 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (63.3% of squared update-to-median distance); encoder.0.weight (25.1% of squared update-to-median distance); encoder.4.weight (8.9% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 1 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012428 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011508.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.068475 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.136951. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 19 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.308365; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.293075, reference=0.199281, robust-z=3.663, risk contribution=0.200; cosine_to_median raw=0.543857, reference=0.905212, robust-z=19.479, risk contribution=0.200; mad_score raw=1.078209, reference=0.935273, robust-z=1.489, risk contribution=0.099.

The client model macro-F1 was 0.007819 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (66.7% of squared update-to-median distance); encoder.0.weight (23.8% of squared update-to-median distance); encoder.4.weight (7.2% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 8 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.011704 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010837.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.033468 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.066935. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 20 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.357957; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.329321, reference=0.199281, robust-z=5.078, risk contribution=0.200; cosine_to_median raw=0.419158, reference=0.905212, robust-z=26.200, risk contribution=0.200; mad_score raw=1.244486, reference=0.935273, robust-z=3.222, risk contribution=0.200.

The client model macro-F1 was 0.072085 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.6% of squared update-to-median distance); encoder.0.weight (23.7% of squared update-to-median distance); encoder.4.weight (11.7% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 3 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012948 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011989.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.083060 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.166119. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 20 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.355405; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.332589, reference=0.199281, robust-z=5.206, risk contribution=0.200; cosine_to_median raw=0.375686, reference=0.905212, robust-z=28.544, risk contribution=0.200; mad_score raw=1.389782, reference=0.935273, robust-z=4.736, risk contribution=0.200.

The client model macro-F1 was 0.002840 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (59.4% of squared update-to-median distance); encoder.0.weight (22.8% of squared update-to-median distance); encoder.4.weight (14.5% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 6 downweights and 2 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013300 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012315.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.080508 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.161015. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 20 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.299453; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.289818, reference=0.199281, robust-z=3.535, risk contribution=0.200; cosine_to_median raw=0.498017, reference=0.905212, robust-z=21.950, risk contribution=0.200; mad_score raw=1.089230, reference=0.935273, robust-z=1.604, risk contribution=0.107.

The client model macro-F1 was 0.008071 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.8% of squared update-to-median distance); encoder.0.weight (24.6% of squared update-to-median distance); encoder.4.weight (7.9% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 9 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.011486 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010635.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.024556 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.049112. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 20 · client15 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.283728; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.285590, reference=0.199281, robust-z=3.370, risk contribution=0.200; cosine_to_median raw=0.554424, reference=0.905212, robust-z=18.909, risk contribution=0.200; relative_norm raw=1.080725, reference=1.000000, robust-z=1.100, risk contribution=0.073.

The client model macro-F1 was 0.005090 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (66.2% of squared update-to-median distance); encoder.0.weight (19.9% of squared update-to-median distance); encoder.4.weight (11.7% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 2 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.011266 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010431.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.008831 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.017662. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 21 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.332639; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.321019, reference=0.199281, robust-z=4.754, risk contribution=0.200; cosine_to_median raw=0.346548, reference=0.905212, robust-z=30.114, risk contribution=0.200; mad_score raw=1.298946, reference=0.935273, robust-z=3.790, risk contribution=0.200.

The client model macro-F1 was 0.013726 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.0% of squared update-to-median distance); encoder.0.weight (23.9% of squared update-to-median distance); encoder.4.weight (11.8% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 4 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.014822 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.013533.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.057742 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.115484. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 21 · client04 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.304119; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.292258, reference=0.199281, robust-z=3.631, risk contribution=0.200; cosine_to_median raw=0.461505, reference=0.905212, robust-z=23.918, risk contribution=0.200; mad_score raw=1.162669, reference=0.935273, robust-z=2.370, risk contribution=0.158.

The client model macro-F1 was 0.010016 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (65.5% of squared update-to-median distance); encoder.0.weight (25.8% of squared update-to-median distance); encoder.4.weight (6.3% of squared update-to-median distance).

Its statistical risk ranked 7 of 15 in this round (rank 1 is highest). Before this round the client had 3 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013643 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012457.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.029222 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.058444. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 21 · client05 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.317425; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.301068, reference=0.199281, robust-z=3.975, risk contribution=0.200; cosine_to_median raw=0.287260, reference=0.905212, robust-z=33.310, risk contribution=0.200; mad_score raw=1.214854, reference=0.935273, robust-z=2.913, risk contribution=0.194.

The client model macro-F1 was 0.004480 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (57.9% of squared update-to-median distance); encoder.0.weight (27.3% of squared update-to-median distance); encoder.4.weight (11.5% of squared update-to-median distance).

Its statistical risk ranked 5 of 15 in this round (rank 1 is highest). Before this round the client had 0 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.014147 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012917.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.042528 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.085055. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 21 · client11 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.343145; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.644094, reference=0.905212, robust-z=14.075, risk contribution=0.200; validation_impact raw=0.059307, reference=-0.008008, robust-z=3.285, risk contribution=0.200; coordinate_median_distance raw=0.260521, reference=0.199281, robust-z=2.391, risk contribution=0.159.

The client model macro-F1 was 0.059307 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.7% of squared update-to-median distance); encoder.0.weight (27.3% of squared update-to-median distance); encoder.4.weight (8.3% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 2 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012223 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011160.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.068248 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.136495. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 21 · client12 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.315832; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.473685, reference=0.905212, robust-z=23.261, risk contribution=0.200; validation_impact raw=0.058369, reference=-0.008008, robust-z=3.239, risk contribution=0.200; coordinate_median_distance raw=0.270997, reference=0.199281, robust-z=2.800, risk contribution=0.187.

The client model macro-F1 was 0.058369 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (56.7% of squared update-to-median distance); encoder.0.weight (29.8% of squared update-to-median distance); encoder.4.weight (10.4% of squared update-to-median distance).

Its statistical risk ranked 6 of 15 in this round (rank 1 is highest). Before this round the client had 2 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012783 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011672.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.040935 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.081869. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 21 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.385668; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.322708, reference=0.199281, robust-z=4.820, risk contribution=0.200; cosine_to_median raw=0.417749, reference=0.905212, robust-z=26.276, risk contribution=0.200; validation_impact raw=0.057967, reference=-0.008008, robust-z=3.219, risk contribution=0.200.

The client model macro-F1 was 0.057967 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.0% of squared update-to-median distance); encoder.0.weight (24.2% of squared update-to-median distance); encoder.4.weight (8.6% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 10 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.015579 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.014224.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.110771 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.221542. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 22 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.368152; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.331973, reference=0.199281, robust-z=5.182, risk contribution=0.200; cosine_to_median raw=0.396712, reference=0.905212, robust-z=27.410, risk contribution=0.200; mad_score raw=1.343083, reference=0.935273, robust-z=4.250, risk contribution=0.200.

The client model macro-F1 was 0.001225 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (63.2% of squared update-to-median distance); encoder.0.weight (19.8% of squared update-to-median distance); encoder.4.weight (14.1% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 7 downweights and 3 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012679 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011774.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.093255 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.186510. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 23 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.381908; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.349225, reference=0.199281, robust-z=5.855, risk contribution=0.200; cosine_to_median raw=0.298862, reference=0.905212, robust-z=32.685, risk contribution=0.200; mad_score raw=1.340486, reference=0.935273, robust-z=4.223, risk contribution=0.200.

The client model macro-F1 was 0.070355 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.2% of squared update-to-median distance); encoder.0.weight (24.6% of squared update-to-median distance); encoder.4.weight (11.3% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 5 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013501 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012536.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.107011 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.214022. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 23 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.370090; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.310500, reference=0.199281, robust-z=4.343, risk contribution=0.200; cosine_to_median raw=0.412211, reference=0.905212, robust-z=26.575, risk contribution=0.200; mad_score raw=1.280821, reference=0.935273, robust-z=3.601, risk contribution=0.200.

The client model macro-F1 was 0.002652 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.6% of squared update-to-median distance); encoder.0.weight (21.0% of squared update-to-median distance); encoder.4.weight (11.5% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 8 downweights and 3 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012195 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011324.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.095193 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.190386. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 23 · client09 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.300000; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.288510, reference=0.199281, robust-z=3.484, risk contribution=0.200; cosine_to_median raw=0.379156, reference=0.905212, robust-z=28.357, risk contribution=0.200; mad_score raw=1.322457, reference=0.935273, robust-z=4.035, risk contribution=0.200.

The client model macro-F1 was 0.063039 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.1% of squared update-to-median distance); encoder.0.weight (23.1% of squared update-to-median distance); encoder.4.weight (12.3% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 1 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010872 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010095.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.025103 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.050206. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 24 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.323078; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.332576, reference=0.199281, robust-z=5.205, risk contribution=0.200; cosine_to_median raw=0.386542, reference=0.905212, robust-z=27.958, risk contribution=0.200; relative_norm raw=1.136382, reference=1.000000, robust-z=1.859, risk contribution=0.124.

The client model macro-F1 was 0.071468 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.6% of squared update-to-median distance); encoder.0.weight (20.8% of squared update-to-median distance); encoder.4.weight (12.7% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 6 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013172 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012196.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.048181 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.096362. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 24 · client09 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.352710; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.328995, reference=0.199281, robust-z=5.065, risk contribution=0.200; cosine_to_median raw=0.378611, reference=0.905212, robust-z=28.386, risk contribution=0.200; mad_score raw=1.500962, reference=0.935273, robust-z=5.895, risk contribution=0.200.

The client model macro-F1 was 0.037357 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (66.3% of squared update-to-median distance); encoder.0.weight (21.4% of squared update-to-median distance); encoder.4.weight (10.0% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 2 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012831 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011881.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.077813 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.155627. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 24 · client12 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.277695; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.311508, reference=0.199281, robust-z=4.382, risk contribution=0.200; cosine_to_median raw=0.402702, reference=0.905212, robust-z=27.087, risk contribution=0.200; relative_norm raw=1.067454, reference=1.000000, robust-z=0.920, risk contribution=0.061.

The client model macro-F1 was 0.007092 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (57.8% of squared update-to-median distance); encoder.0.weight (29.1% of squared update-to-median distance); encoder.4.weight (10.2% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 3 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012284 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011374.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.002798 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.005595. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 24 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.292960; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.279947, reference=0.199281, robust-z=3.150, risk contribution=0.200; cosine_to_median raw=0.399570, reference=0.905212, robust-z=27.256, risk contribution=0.200; mad_score raw=1.154056, reference=0.935273, robust-z=2.280, risk contribution=0.152.

The client model macro-F1 was 0.002423 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (58.1% of squared update-to-median distance); encoder.0.weight (25.9% of squared update-to-median distance); encoder.4.weight (12.3% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 11 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010820 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010019.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.018063 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.036127. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 25 · client01 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.284942; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.278024, reference=0.199281, robust-z=3.075, risk contribution=0.200; cosine_to_median raw=0.612544, reference=0.905212, robust-z=15.776, risk contribution=0.200; relative_norm raw=1.137449, reference=1.000000, robust-z=1.874, risk contribution=0.125.

The client model macro-F1 was 0.069609 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (67.5% of squared update-to-median distance); encoder.0.weight (24.0% of squared update-to-median distance); encoder.4.weight (6.9% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 1 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012154 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011179.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.010045 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.020090. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 25 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.347842; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.354285, reference=0.199281, robust-z=6.053, risk contribution=0.200; cosine_to_median raw=0.302666, reference=0.905212, robust-z=32.480, risk contribution=0.200; mad_score raw=1.152314, reference=0.935273, robust-z=2.262, risk contribution=0.151.

The client model macro-F1 was 0.070802 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (59.9% of squared update-to-median distance); encoder.0.weight (25.7% of squared update-to-median distance); encoder.4.weight (12.3% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 7 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.015375 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.014145.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.072945 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.145889. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 25 · client11 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.278284; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.300379, reference=0.199281, robust-z=3.948, risk contribution=0.200; cosine_to_median raw=0.472958, reference=0.905212, robust-z=23.300, risk contribution=0.200; relative_norm raw=1.091847, reference=1.000000, robust-z=1.252, risk contribution=0.083.

The client model macro-F1 was 0.000639 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.5% of squared update-to-median distance); encoder.0.weight (25.1% of squared update-to-median distance); encoder.4.weight (10.5% of squared update-to-median distance).

Its statistical risk ranked 5 of 15 in this round (rank 1 is highest). Before this round the client had 3 downweights and 1 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013189 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012134.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.003386 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.006773. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 25 · client12 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.320259; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.330743, reference=0.199281, robust-z=5.133, risk contribution=0.200; cosine_to_median raw=0.363227, reference=0.905212, robust-z=29.215, risk contribution=0.200; relative_norm raw=1.116829, reference=1.000000, robust-z=1.593, risk contribution=0.106.

The client model macro-F1 was 0.005470 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (59.9% of squared update-to-median distance); encoder.0.weight (24.1% of squared update-to-median distance); encoder.4.weight (12.5% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 4 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013959 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012843.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.045362 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.090725. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 26 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.396605; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.367177, reference=0.199281, robust-z=6.556, risk contribution=0.200; cosine_to_median raw=0.268558, reference=0.905212, robust-z=34.318, risk contribution=0.200; mad_score raw=1.213443, reference=0.935273, robust-z=2.899, risk contribution=0.193.

The client model macro-F1 was 0.005702 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.8% of squared update-to-median distance); encoder.0.weight (21.1% of squared update-to-median distance); encoder.4.weight (14.2% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 8 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.017131 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.015642.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.121708 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.243416. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 26 · client05 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.278308; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.298653, reference=0.199281, robust-z=3.880, risk contribution=0.200; cosine_to_median raw=0.303726, reference=0.905212, robust-z=32.423, risk contribution=0.200; validation_impact raw=0.026315, reference=-0.008008, robust-z=1.675, risk contribution=0.112.

The client model macro-F1 was 0.026315 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (59.5% of squared update-to-median distance); encoder.0.weight (25.4% of squared update-to-median distance); encoder.4.weight (10.5% of squared update-to-median distance).

Its statistical risk ranked 7 of 15 in this round (rank 1 is highest). Before this round the client had 1 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013966 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012751.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.003411 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.006823. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 26 · client09 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.322483; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.287437, reference=0.199281, robust-z=3.442, risk contribution=0.200; cosine_to_median raw=0.402243, reference=0.905212, robust-z=27.112, risk contribution=0.200; validation_impact raw=0.068989, reference=-0.008008, robust-z=3.757, risk contribution=0.200.

The client model macro-F1 was 0.068989 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (63.9% of squared update-to-median distance); encoder.0.weight (24.1% of squared update-to-median distance); encoder.4.weight (9.4% of squared update-to-median distance).

Its statistical risk ranked 5 of 15 in this round (rank 1 is highest). Before this round the client had 3 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013209 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012061.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.047586 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.095172. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 26 · client11 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.387012; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.289950, reference=0.199281, robust-z=3.541, risk contribution=0.200; cosine_to_median raw=0.567589, reference=0.905212, robust-z=18.199, risk contribution=0.200; validation_impact raw=0.070736, reference=-0.008008, robust-z=3.842, risk contribution=0.200.

The client model macro-F1 was 0.070736 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (66.6% of squared update-to-median distance); encoder.0.weight (24.7% of squared update-to-median distance); encoder.4.weight (7.1% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 4 downweights and 1 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013887 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012680.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.112115 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.224230. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 26 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.351434; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.293858, reference=0.199281, robust-z=3.693, risk contribution=0.200; cosine_to_median raw=0.443929, reference=0.905212, robust-z=24.865, risk contribution=0.200; validation_impact raw=0.066186, reference=-0.008008, robust-z=3.620, risk contribution=0.200.

The client model macro-F1 was 0.066186 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.3% of squared update-to-median distance); encoder.0.weight (26.9% of squared update-to-median distance); encoder.4.weight (6.9% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 12 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013949 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012736.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.076537 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.153073. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 26 · client15 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.301203; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: cosine_to_median raw=0.643179, reference=0.905212, robust-z=14.125, risk contribution=0.200; validation_impact raw=0.067610, reference=-0.008008, robust-z=3.690, risk contribution=0.200; coordinate_median_distance raw=0.243213, reference=0.199281, robust-z=1.716, risk contribution=0.114.

The client model macro-F1 was 0.067610 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (66.7% of squared update-to-median distance); encoder.0.weight (21.0% of squared update-to-median distance); encoder.4.weight (10.1% of squared update-to-median distance).

Its statistical risk ranked 6 of 15 in this round (rank 1 is highest). Before this round the client had 3 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.011546 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010542.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.026306 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.052611. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 27 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.325376; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.358720, reference=0.199281, robust-z=6.226, risk contribution=0.200; cosine_to_median raw=0.217665, reference=0.905212, robust-z=37.062, risk contribution=0.200; mad_score raw=1.190682, reference=0.935273, robust-z=2.661, risk contribution=0.177.

The client model macro-F1 was 0.070386 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (66.2% of squared update-to-median distance); encoder.0.weight (19.1% of squared update-to-median distance); encoder.4.weight (13.0% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 9 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013554 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012586.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.050479 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.100958. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 27 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.406861; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.367554, reference=0.199281, robust-z=6.571, risk contribution=0.200; cosine_to_median raw=0.344527, reference=0.905212, robust-z=30.223, risk contribution=0.200; mad_score raw=1.590847, reference=0.935273, robust-z=6.831, risk contribution=0.200.

The client model macro-F1 was 0.000567 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.5% of squared update-to-median distance); encoder.0.weight (20.8% of squared update-to-median distance); encoder.4.weight (13.0% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 9 downweights and 5 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.014235 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.013218.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.131964 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.263928. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 27 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.350112; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.332354, reference=0.199281, robust-z=5.196, risk contribution=0.200; cosine_to_median raw=0.352439, reference=0.905212, robust-z=29.797, risk contribution=0.200; mad_score raw=1.411231, reference=0.935273, robust-z=4.960, risk contribution=0.200.

The client model macro-F1 was 0.000135 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (63.2% of squared update-to-median distance); encoder.0.weight (23.3% of squared update-to-median distance); encoder.4.weight (9.9% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 13 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012546 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011650.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.075215 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.150431. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 28 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.400000; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.376062, reference=0.199281, robust-z=6.903, risk contribution=0.200; cosine_to_median raw=0.365402, reference=0.905212, robust-z=29.098, risk contribution=0.200; mad_score raw=1.254651, reference=0.935273, robust-z=3.328, risk contribution=0.200.

The client model macro-F1 was 0.071505 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (63.6% of squared update-to-median distance); encoder.0.weight (21.7% of squared update-to-median distance); encoder.4.weight (12.8% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 10 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.014959 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.013851.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.125103 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.250206. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 28 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.401504; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.345135, reference=0.199281, robust-z=5.695, risk contribution=0.200; cosine_to_median raw=0.388103, reference=0.905212, robust-z=27.874, risk contribution=0.200; mad_score raw=1.340200, reference=0.935273, robust-z=4.220, risk contribution=0.200.

The client model macro-F1 was 0.000567 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (63.2% of squared update-to-median distance); encoder.0.weight (19.0% of squared update-to-median distance); encoder.4.weight (14.4% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 10 downweights and 5 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013837 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012812.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.126607 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.253214. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 28 · client09 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.297166; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.317651, reference=0.199281, robust-z=4.622, risk contribution=0.200; cosine_to_median raw=0.331202, reference=0.905212, robust-z=30.942, risk contribution=0.200; mad_score raw=1.159839, reference=0.935273, robust-z=2.340, risk contribution=0.156.

The client model macro-F1 was 0.060780 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (66.8% of squared update-to-median distance); encoder.0.weight (20.0% of squared update-to-median distance); encoder.4.weight (10.7% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 4 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012516 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011589.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.022269 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.044538. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 28 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.295880; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.279773, reference=0.199281, robust-z=3.143, risk contribution=0.200; cosine_to_median raw=0.462046, reference=0.905212, robust-z=23.889, risk contribution=0.200; mad_score raw=1.176407, reference=0.935273, robust-z=2.513, risk contribution=0.168.

The client model macro-F1 was 0.000555 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (61.9% of squared update-to-median distance); encoder.0.weight (24.6% of squared update-to-median distance); encoder.4.weight (10.4% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 14 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.010995 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.010181.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.020983 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.041966. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 29 · client01 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.298523; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.292575, reference=0.199281, robust-z=3.643, risk contribution=0.200; cosine_to_median raw=0.529356, reference=0.905212, robust-z=20.260, risk contribution=0.200; mad_score raw=1.066746, reference=0.935273, robust-z=1.370, risk contribution=0.091.

The client model macro-F1 was 0.005130 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (67.0% of squared update-to-median distance); encoder.0.weight (25.4% of squared update-to-median distance); encoder.4.weight (5.6% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 2 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012884 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011851.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.023626 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.047252. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 29 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.329275; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.346544, reference=0.199281, robust-z=5.750, risk contribution=0.200; cosine_to_median raw=0.352972, reference=0.905212, robust-z=29.768, risk contribution=0.200; mad_score raw=1.143270, reference=0.935273, robust-z=2.167, risk contribution=0.144.

The client model macro-F1 was 0.069286 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (65.5% of squared update-to-median distance); encoder.0.weight (20.6% of squared update-to-median distance); encoder.4.weight (12.2% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 11 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.014961 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.013765.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.054377 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.108755. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 29 · client09 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.397787; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.402488, reference=0.199281, robust-z=7.935, risk contribution=0.200; cosine_to_median raw=0.198037, reference=0.905212, robust-z=38.120, risk contribution=0.200; mad_score raw=1.677883, reference=0.935273, robust-z=7.738, risk contribution=0.200.

The client model macro-F1 was 0.062272 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.7% of squared update-to-median distance); encoder.0.weight (21.2% of squared update-to-median distance); encoder.4.weight (13.4% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 5 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.016971 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.015613.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.122890 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.245780. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 29 · client11 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.279101; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.292252, reference=0.199281, robust-z=3.630, risk contribution=0.200; cosine_to_median raw=0.520939, reference=0.905212, robust-z=20.714, risk contribution=0.200; validation_impact raw=0.009891, reference=-0.008008, robust-z=0.873, risk contribution=0.058.

The client model macro-F1 was 0.009891 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (63.1% of squared update-to-median distance); encoder.0.weight (23.0% of squared update-to-median distance); encoder.4.weight (12.0% of squared update-to-median distance).

Its statistical risk ranked 6 of 15 in this round (rank 1 is highest). Before this round the client had 5 downweights and 1 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.012945 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.011909.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.004204 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.008408. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 29 · client12 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.285792; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.351697, reference=0.199281, robust-z=5.952, risk contribution=0.200; cosine_to_median raw=0.272977, reference=0.905212, robust-z=34.080, risk contribution=0.200; relative_norm raw=1.084326, reference=1.000000, robust-z=1.150, risk contribution=0.077.

The client model macro-F1 was 0.007357 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (61.9% of squared update-to-median distance); encoder.0.weight (26.4% of squared update-to-median distance); encoder.4.weight (9.0% of squared update-to-median distance).

Its statistical risk ranked 5 of 15 in this round (rank 1 is highest). Before this round the client had 5 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.014888 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.013698.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.010895 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.021791. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 29 · client13 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.297484; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.329746, reference=0.199281, robust-z=5.095, risk contribution=0.200; cosine_to_median raw=0.380168, reference=0.905212, robust-z=28.302, risk contribution=0.200; mad_score raw=1.048210, reference=0.935273, robust-z=1.177, risk contribution=0.078.

The client model macro-F1 was 0.004262 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (65.0% of squared update-to-median distance); encoder.0.weight (23.6% of squared update-to-median distance); encoder.4.weight (8.2% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 15 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.014019 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012898.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.022587 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.045173. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 30 · client02 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.296213; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.331906, reference=0.199281, robust-z=5.179, risk contribution=0.200; cosine_to_median raw=0.339534, reference=0.905212, robust-z=30.492, risk contribution=0.200; mad_score raw=1.140526, reference=0.935273, robust-z=2.139, risk contribution=0.143.

The client model macro-F1 was 0.035490 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.4% of squared update-to-median distance); encoder.0.weight (23.8% of squared update-to-median distance); encoder.4.weight (11.6% of squared update-to-median distance).

Its statistical risk ranked 5 of 15 in this round (rank 1 is highest). Before this round the client had 12 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013746 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012689.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.021316 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.042632. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 30 · client05 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.335468; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.363611, reference=0.199281, robust-z=6.417, risk contribution=0.200; cosine_to_median raw=0.208921, reference=0.905212, robust-z=37.533, risk contribution=0.200; mad_score raw=1.260265, reference=0.935273, robust-z=3.387, risk contribution=0.200.

The client model macro-F1 was 0.071206 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (60.4% of squared update-to-median distance); encoder.0.weight (24.1% of squared update-to-median distance); encoder.4.weight (11.5% of squared update-to-median distance).

Its statistical risk ranked 4 of 15 in this round (rank 1 is highest). Before this round the client had 2 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.015090 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.013929.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.060571 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.121141. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 30 · client06 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.342953; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.311642, reference=0.199281, robust-z=4.388, risk contribution=0.200; cosine_to_median raw=0.440568, reference=0.905212, robust-z=25.046, risk contribution=0.200; mad_score raw=1.229921, reference=0.935273, robust-z=3.070, risk contribution=0.200.

The client model macro-F1 was 0.002343 below the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (64.0% of squared update-to-median distance); encoder.0.weight (22.1% of squared update-to-median distance); encoder.4.weight (10.6% of squared update-to-median distance).

Its statistical risk ranked 2 of 15 in this round (rank 1 is highest). Before this round the client had 11 downweights and 5 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013128 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012118.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.068056 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.136111. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 30 · client09 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.366168; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.370557, reference=0.199281, robust-z=6.688, risk contribution=0.200; cosine_to_median raw=0.270985, reference=0.905212, robust-z=34.187, risk contribution=0.200; mad_score raw=1.783775, reference=0.935273, robust-z=8.842, risk contribution=0.200.

The client model macro-F1 was 0.061712 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (65.4% of squared update-to-median distance); encoder.0.weight (19.2% of squared update-to-median distance); encoder.4.weight (12.7% of squared update-to-median distance).

Its statistical risk ranked 1 of 15 in this round (rank 1 is highest). Before this round the client had 6 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.015294 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.014117.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.091270 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.182541. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.

### Round 30 · client12 · accepted_downweighted

All 7 M5 checks passed and the fresh M4 attestation was admissible; no trust failure caused this decision.

The contribution was accepted at half of its example-count weight. Its gated-composite score was 0.341359; the downweight and quarantine thresholds were 0.274897 and 0.409155.

The leading scalar drivers were: coordinate_median_distance raw=0.326671, reference=0.199281, robust-z=4.974, risk contribution=0.200; cosine_to_median raw=0.412707, reference=0.905212, robust-z=26.548, risk contribution=0.200; mad_score raw=1.259284, reference=0.935273, robust-z=3.376, risk contribution=0.200.

The client model macro-F1 was 0.061079 above the incoming global model on the isolated validation split.

Policy comparison: tpm_only=accepted, statistics_only=accepted, sequential=accepted, gated_composite=accepted_downweighted.

The leading tensor drivers were: encoder.2.weight (62.5% of squared update-to-median distance); encoder.0.weight (26.9% of squared update-to-median distance); encoder.4.weight (7.8% of squared update-to-median distance).

Its statistical risk ranked 3 of 15 in this round (rank 1 is highest). Before this round the client had 6 downweights and 0 quarantines. The actual retained-weight fraction was 0.50.

Its admitted influence on the effective aggregate was 0.013301 in L2 distance. Restoring full weight while holding the round fixed would move the aggregate by 0.012278.

Holding trust, peers, and calibration fixed, a composite reduction of 0.000000 would restore non-zero weight and a reduction of 0.066462 would restore full weight. With trust risk fixed at zero, these correspond to statistical-risk reductions of 0.000000 and 0.132923. This is a score-level counterfactual and does not prescribe one unique indicator or tensor change.

This explains the configured admission rule and update geometry. It does not prove malicious intent; the declared execution condition contains no injected attack.
