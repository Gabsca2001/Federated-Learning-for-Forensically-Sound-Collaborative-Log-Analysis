# Experimental evidence overview

The [complete catalogue](CATALOG.md) registers every retained study directory.
This page highlights the current reading path; it does not replace source-bound
reports or merge different protocols into one performance claim.

## Current retrospective analysis

| Reading order | Publication | Interpretation |
| --- | --- | --- |
| 1 | [Late correction and earlier selector failures](admission/revision-endpoint-retrospective-groups-v2/README.md) | Exposure and late correction do not establish decontamination |
| 2 | [V4 full-origin recovery](admission/revision-attribution-origin-recovery-v1/README.md) | Correct known-group removal restores its declared clean counterfactual; attribution remains imperfect |
| 3 | [V4 diagnosis](admission/revision-selector-diagnosis-v1/README.md) | Rare-class utility risk and intermittent-score dilution explain distinct attribution failures |
| 4 | [V5 assessment](admission/revision-episodic-attribution-recovery-v1/README.md) | Utility/actor separation reduces selected benign memberships to zero in the new fixed assessment, with remaining misses |
| 5 | [V5 individual/joint interpretation](admission/revision-episodic-attribution-recovery-v1/GROUP_INTERPRETATION.md) | Four of six joint removals outperform every individual; exact recovery and zero ASR remain separate |

## Architecture, trust and formal evidence

- [Formal correspondence](chain-witness/revision-final-formal-correspondence-v2/README.md)
- [External TSA integration](chain-witness/revision-external-tsa-v2/README.md)
- [Unified representative M2–M8 chain](chain-witness/revision-unified-chain-v1/README.md)
- [Administrative boundary](chain-witness/revision-witness-admin-boundary-v1/REPORT.md)

## Gates, containment and comparisons

- [Original gate mechanism audit](gates-probes/revision-gate-mechanism-audit-v1/README.md)
- [Completed capped-final study](gates-probes/revision-capped-final-v1/REPORT.md): structural
  coefficient/availability improvements coexist with negative defense outcomes.
- [Coherent learned-endpoint DBA](admission/revision-coherent-endpoint-dba-v1/README.md):
  positive containment within the declared protocol, with residual model differences.
- [Literature and accepted-requirement correspondence](../docs/guide/REQUIREMENTS.md)

All older milestone, adaptive, reference-coherence, feasibility and failed studies
remain in the catalogue. Publication directories keep their original bytes and
paths. A report's historical "next steps" section is not the current project plan.

`make evidence-list` lists the catalogue. `make evidence-check` validates the
stored flat checksum index of the selected publication; fresh numerical replay,
TPM appraisal and independent authentication remain separate operations.
