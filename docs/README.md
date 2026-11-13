# Documentation index

The maintained guide describes the repository state as of **13 November 2026**.
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
| Gate and probe research: what holds, what failed, what is open | [Gate research summary](records/GATE_RESEARCH_HANDOFF.md) |
| Where large evidence is stored and how to restore it | [Artifact offload](records/ARTIFACT_OFFLOAD.md) |
| Remaining work | [Implementation plan](IMPLEMENTATION_PLAN.md) |
| Full list of original technical/protocol documents | [Reference catalogue](REFERENCE_INDEX.md) |
| Retained experimental publications | [Results overview](../results/README.md) and [complete catalogue](../results/CATALOG.md) |
| Writing, index and evidence-retention rules | [Maintenance](guide/MAINTENANCE.md) |

## Formal reference

[Formal theorems](formal/FORMAL_MODEL_THEOREMS.md), [round derivation](formal/ROUND_DERIVATION.md),
[committed-input coverage](formal/INGESTION_COVERAGE.md), [semantic reviews](formal/SEMANTIC_REVIEWS.md),
[multiround derivation](formal/MULTIROUND_DERIVATION.md) and
[counterfactual replay](formal/COUNTERFACTUAL_REPLAY.md) retain the exact definitions,
assumptions and release correspondence. The consolidation does not rewrite them.

## Reading versioned documents

Only the maintained pages sit at the top of `docs/`. Everything else is a
stable versioned reference, grouped by theme:

| Folder | Contents |
| --- | --- |
| `milestones/` | M3–M8 procedures and the Data24 dataset description |
| `admission-gates/` | Admission, adaptive-attack, bounded-influence, envelope and gate study reports and protocols |
| `formal/` | Theorems, derivations, coverage, semantic reviews and counterfactual replay |
| `measurement/` | Overhead, runtime, attestation-failure, external generalisation and publication readiness |
| `witness-chain/` | Submission evidence, witnesses and external TSA |
| `records/` | Dated audits, supervisor updates, consolidation notes, the gate handoff and the offload record |

These files are not parallel current guides. Their historical execution notes and
test totals must be read within the stated release. Later outcomes are indexed
through the maintained guides rather than appended repeatedly to old reports.
