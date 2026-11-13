# Implementation status

Status date: **9 November 2026**. This is the maintained state summary. Dated
protocols and reports describe their own releases; their historical "pending",
"running" or "current" statements are not live process indicators.

## Implemented and exercised

| Area | Current scope | Evidence entry |
| --- | --- | --- |
| M2 to M8 integration | Shared contracts and a representative witnessed path through real M7 products and M8 recovery; profiles remain explicit | [System model](SYSTEM_MODEL.md), [selected-chain validation](UNIFIED_CHAIN_VALIDATION.md) |
| Formal derivation | Provenance, decision dependency, effective weights and semantic review are distinct; manual proofs remain conditional | [Theorems](formal/FORMAL_MODEL_THEOREMS.md), [final correspondence](../results/chain-witness/revision-final-formal-correspondence-v2/README.md) |
| Input and submission coverage | Committed occurrence outcomes, receipt-relative inventory checks and separately witnessed eligibility | [Coverage](formal/INGESTION_COVERAGE.md), [receipts](witness-chain/SUBMISSION_EVIDENCE.md), [external TSA](../results/chain-witness/revision-external-tsa-v2/README.md) |
| Multiround investigation | Authenticated checkpoint/product graph, structural blast radius, direct interventions and genuine corrected-parent retraining | [Graph](formal/MULTIROUND_DERIVATION.md), [replay](formal/COUNTERFACTUAL_REPLAY.md) |
| DBA and comparisons | Distributed/full triggers, individual components, matched-input baselines and separately qualified gradient-history studies | [Experimental findings](guide/EXPERIMENTS.md) |
| ToN-IoT diagnosis | Benign-reference kNN hybrid: native macro-F1 0.9086/FPR1.87%, MITM17-20/130; common-minute F1 0.6812 with 20% FPR; general novel-family performance remains weak; 74 focused passes | [Independent-dataset validation](TON_IOT_VALIDATION.md) |
| V5 retrospective groups | Utility-risk separation, clean-calibrated repeated magnitude episodes, new allocations and full-origin removal controls | [V5 publication](../results/admission/revision-episodic-attribution-recovery-v1/README.md) |

## Findings that constrain claims

The standard optional admission file selects `gated_composite`; M5 does not
install that file automatically. The unified witnessed profile explicitly
selects `tpm_only`. A policy default is not a ranking of empirical effectiveness.

The capped-final study completed its declared histories and improved clean
availability/utility under its transformed coefficient contract, but did not
satisfy its poisoning-defense objective. Later coherent endpoint studies contain
positive containment examples with residual model differences. V5 improves
selected-group precision on the new assessment while missing additional
scheduled memberships. These findings describe different protocols and cannot
be pooled as a single defense success rate.

## Open or deferred

- Independent witness administration and reference custody remain unproved on
  the locally shared administrative deployment.
- ToN-IoT frozen transfer and the declared chronological F1 extensions remain
  unsuccessful. A separate known-family offline benchmark reaches 0.9087 mean
  macro-F1, with globally interleaved family dates and 20.07% benign false
  positives. Neither population supports operational readiness or unseen-family
  robustness. A same-role feature extension confirms strong benign capture-period
  dependence; the threshold-gap control alone changes no test decisions.
  Source-IP windows improve native benign classification but leave common-minute
  F1 and unseen MITM detection weak; coincidence is separated from attacked-host
  alerts. Benign-reference novelty adds limited MITM detection at higher false
  alert rates and does not establish general novel-family recognition.
  Fresh independent benign captures, future-global assessment and
  stronger physical-connection identity remain open. The earlier Data22
  checkpoint discrepancy remains documented. See [ToN-IoT validation](TON_IOT_VALIDATION.md).
- General automatic attacker exclusion, norm-limited successful evasion and
  robust out-of-distribution calibration remain unvalidated.
- FedGradTrace retains 25 complete histories and seven reproduced numerical
  failures under qualified interpretations, rather than a complete original
  system reproduction.
- Later technical results require a controlled manuscript alignment pass;
  this documentation consolidation does not edit the thesis.

The [requirement correspondence](guide/REQUIREMENTS.md) distinguishes the accepted
retrospective programme from additional automatic-defense research. The
[implementation plan](IMPLEMENTATION_PLAN.md) contains remaining work only.

## Validation interpretation

Historical full-suite counts belong to their source releases. The V5 study
records 40 focused passes and fresh replay of 50 clean calibration rounds,
210 source rounds and 630 recovery rounds. These are not a new full-suite count.
`make docs-check` checks documentation structure and retained Markdown integrity;
`make evidence-check` checks a selected publication's stored checksum index.
Neither operation retrains the experiment or obtains new TPM evidence.
