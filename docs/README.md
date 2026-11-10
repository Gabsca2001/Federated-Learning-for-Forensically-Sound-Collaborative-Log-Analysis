# Documentation index

The maintained guide describes the repository state as of **9 November 2026**.
The following reading order separates system behavior, experimental findings
and versioned evidence.

| Purpose | Entry point |
| --- | --- |
| Current implementation and limitations | [Status](STATUS.md) |
| First visit: diagram, round walkthrough, code map | [Architecture map](guide/ARCHITECTURE_MAP.md) |
| Terms and identifiers (M1–M8, V4/V5, profiles) | [Glossary](guide/GLOSSARY.md) |
| Architecture and M2–M8 composition | [Framework](guide/FRAMEWORK.md) |
| Effective defaults and four original policies | [Admission and defenses](guide/ADMISSION.md) |
| Attack outcomes, comparisons and retrospective recovery | [Experimental findings](guide/EXPERIMENTS.md) |
| Accepted email requirements | [Requirement correspondence](guide/REQUIREMENTS.md) |
| Installation, Make targets and controlled execution | [Reproducibility](guide/REPRODUCIBILITY.md) |
| Official ToN-IoT source and representation checks | [Independent-dataset preflight](TON_IOT_VALIDATION.md) |
| Remaining work | [Implementation plan](IMPLEMENTATION_PLAN.md) |
| Full list of original technical/protocol documents | [Reference catalogue](REFERENCE_INDEX.md) |
| Retained experimental publications | [Results overview](../results/README.md) and [complete catalogue](../results/CATALOG.md) |
| Writing, index and evidence-retention rules | [Maintenance](guide/MAINTENANCE.md) |

## Formal reference

[Formal theorems](FORMAL_MODEL_THEOREMS.md), [round derivation](ROUND_DERIVATION.md),
[committed-input coverage](INGESTION_COVERAGE.md), [semantic reviews](SEMANTIC_REVIEWS.md),
[multiround derivation](MULTIROUND_DERIVATION.md) and
[counterfactual replay](COUNTERFACTUAL_REPLAY.md) retain the exact definitions,
assumptions and release correspondence. The consolidation does not rewrite them.

## Reading versioned documents

The root of `docs/` also retains older milestone procedures, locked protocols,
dated audits and profile-specific research reports. Those files are stable
references, not parallel current guides. Their historical execution notes and
test totals must be read within the stated release. Later outcomes are indexed
through the maintained guides rather than appended repeatedly to old reports.
