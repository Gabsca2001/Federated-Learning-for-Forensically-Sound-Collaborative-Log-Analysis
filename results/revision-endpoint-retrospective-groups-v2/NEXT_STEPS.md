# Next technical decisions after this validation

This document is a proposed follow-up, not an implemented detector or a success
claim. Preserve the failed V2/V3 transfer and every prior containment result.

## Retrospective selection requires revision

The current pair-conditioned rules look for increases in similarity. They are
not direct magnitude anomaly tests. The new attack family can export very large
Byzantine endpoint vectors without creating a sufficiently unusual pair score.
Conversely, benign non-IID allocation changes can exceed that pair reference.
Do not repair these results by selecting thresholds from known attackers.

A new separately declared method should distinguish individual evidence of
abnormal update magnitude/validation impact from evidence of coordinated
behavior across clients. Use the recorded per-tensor/temporal observations for
group hypotheses, and keep individual anomalies distinct from collusion claims.
Fit and calibrate on clean-only histories appropriate to the honest optimizer;
evaluate on actual distinct allocations, different adversarial identities and
both distributed/full variants. Retain all zero-candidate and false-member cases.

Fresh allocations used only for assessment must not be chosen by consulting
their attack outcomes. The current six histories are development evidence after
this analysis and cannot become an independent confirmation set for a new rule.
Do not call same-population repartitions an independent dataset.

Include a norm-constrained/less conspicuous adversary family as a separately
frozen control, with the same effectiveness checks as the current unrestricted
endpoint attacker. The existing six-factor endpoint grid is not an exhaustive
directional or stealth attack. Ineffective controls cannot certify resistance.

## Recovery must distinguish late correction from rebuilding history

Late R10 omission leaves the R1-9 source parent intact. If the target is actual
recovery, the relevant further experiment starts from a preserved checkpoint
before the first contribution attributed to the suspect group and retrains
every affected later round at corrected parents. Surviving historical updates
cannot simply be reused when their original bases differ.

Keep two roles separate: (a) oracle-known attackers as a diagnostic ceiling and
(b) groups genuinely selected by the detector, including wrong or empty groups.
Include size/sample-mass benign removal controls and correctly matched clean
references where possible. An earlier checkpoint is trusted clean only under
an explicit assumption; an authentic hash alone does not prove cleanliness.

For any continuing attacker that survives the intervention, a full adversarial
counterfactual requires fresh local poisoned training and the declared adaptive
queries at each corrected parent. Replaying original alphas/updates is a
conditional replay and must not be labelled a newly adaptive attacker.

## Keep defense claims separate

The earlier FLTrust/norm-only warm-start containment result remains a measured
preventive result for its restricted endpoint family. The present retrospective
selection failure and late-recovery failure do not invalidate the numeric zero
ASR observations, and those observations do not validate attribution or recovery.
Useful clean learning from a less mature model and longer horizons still need
their own bounded protocol before operational integration is claimed.

No automatic quarantine, new default, thesis edit, ToN-IoT acquisition or external
witness deployment is introduced. Continue compact metadata/checkpoint retention,
an explicit output budget and the 8 GiB host free-space floor.
