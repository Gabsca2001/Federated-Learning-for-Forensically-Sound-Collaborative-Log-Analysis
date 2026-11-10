# Federated Learning for Forensically-Sound Collaborative Log Analysis

An auditable research framework for controlled Zeek-log ingestion, federated
learning, authenticated contribution admission, retrospective investigation and
evidence preservation. The implementation distinguishes provenance, effective
numerical influence and attributed semantic assessment.

## What the repository demonstrates

The central result is the architecture, not a detection score. Every round,
admission decision, checkpoint and investigative product is signed, linked to
its inputs and reproducible by an independent verifier. Successful and failed
experiments are retained under the same verification contracts, so a negative
predictive or defensive outcome remains attributable and reconstructible.
Predictive and defensive findings are conditional on their declared protocols;
the forensic properties hold under the stated cryptographic and input assumptions.

**Start here:** the [architecture map](docs/guide/ARCHITECTURE_MAP.md) shows the
pipeline, one round step by step, where each stage lives in the code and which
reading path fits each goal.

The maintained documentation was consolidated on **9 November 2026**. The
[documentation index](docs/README.md) is the main entry point; the
[implementation status](docs/STATUS.md) records supported claims and open work.

## Framework

The reference learning path comprises Data24 preparation (M2), client partitions
and clean baselines (M3), identity and attestation (M4), secure rounds (M5),
Byzantine comparisons (M6), investigation products (M7) and preservation (M8).
M1 is a separate acquisition/contract demonstration; Data24 is not retrospectively
attested through that demonstration.

The formal extensions provide submission receipts, inventory accounting,
committed-input coverage, append-only semantic review, multiround derivation,
structural blast-radius queries and explicitly defined counterfactual replay.
A separately versioned witnessed profile composes an actual selected M2–M8 path.
Experimental defenses remain distinct profiles with their own evidence.

| Topic | Maintained guide |
| --- | --- |
| Pipeline diagram, round walkthrough, code locations and reading paths | [Architecture map](docs/guide/ARCHITECTURE_MAP.md) |
| Terms, stage identifiers and experimental vocabulary | [Glossary](docs/guide/GLOSSARY.md) |
| Components and integration boundaries | [Framework](docs/guide/FRAMEWORK.md) |
| TPM-only, statistics-only, sequential and gated-composite policies | [Admission and defenses](docs/guide/ADMISSION.md) |
| DBA, literature comparisons, failed defenses and V5 groups | [Experimental findings](docs/guide/EXPERIMENTS.md) |
| Accepted supervisor requirements and remaining obligations | [Requirement correspondence](docs/guide/REQUIREMENTS.md) |
| Installation, verification and controlled execution | [Reproducibility](docs/guide/REPRODUCIBILITY.md) |
| Official ToN-IoT acquisition, source-IP/novelty diagnosis and qualified F1 assessments | [Independent-dataset validation](docs/TON_IOT_VALIDATION.md) |
| All retained studies | [Results catalogue](results/CATALOG.md) |

## Local use

The full environment uses Linux/WSL2, Python 3.11+, OpenSSL and Docker Compose for
the selected software-TPM workflows. Numerical-only checks do not require a new
Docker deployment. The root Makefile provides explicit entry points:

```bash
make help
make check
make docs-check
make evidence-list
make evidence-check
```

On a new environment, `make setup` installs the declared extras. `make test`
runs the full test suite; `make test-formal` and `make test-groups` select relevant
subsets. `make validate` retains the package/lint/test/fixture workflow. The small
fixture is an artifact-contract check, not a reference training campaign.

Dataset downloads, M2–M3 reconstruction and profile-specific runtime commands
are documented in [Reproducibility](docs/guide/REPRODUCIBILITY.md). Existing output
paths are protected. Neither `make` nor the documentation checks launch attack
campaigns, acquire timestamps or modify the manuscript implicitly.

## Evidence and interpretation

V5 separates utility risk from repeated update-magnitude anomalies. On the fixed
14-history assessment, selected benign memberships fall from eight to zero,
while selected adversarial memberships fall from 24 to 22. All six effective raw
attack cases have complete selected groups and exact same-excluded-roster clean
recovery after full-origin retraining. Remaining misses and ineffective
norm-limited controls prevent a general automatic-exclusion claim.

These results concern retrospective analysis. Earlier positive containment cases,
negative gate/aggregation studies, literature adaptations and interrupted runs
remain available in the [results overview](results/README.md). A verified report
establishes its declared checks; it does not imply successful defense criteria.

Submission completeness is relative to the declared evidence/input boundary.
Structural reachability is relative to authenticated supplied manifests. External
TSA integration has been demonstrated; independent witness administration has
not. Software-TPM validation does not establish physical-TPM deployment.

## Repository layout

| Directory | Role |
| --- | --- |
| `src/fl_forensics/` | Package, CLI, artifact contracts and verifiers |
| `configs/` | Profile-specific contracts and schemas |
| `scripts/` | Runtime orchestration, research adapters and repository checks |
| `tests/` | Unit, integration, tamper and verifier checks |
| `docs/` | Maintained guide plus stable versioned references |
| `results/` | Retained study publications and the complete catalogue |
| `artifacts/` | Local runtime evidence, trust state and preserved releases |
| `data/` | Controlled local dataset inputs |

Many local research files have not been committed. Catalogue membership is not a
claim that an artifact is tracked, sanitized for public release or independently
authenticated. Historical evidence retains its original paths and bytes; the
[maintenance policy](docs/guide/MAINTENANCE.md) defines the documentation boundary.
