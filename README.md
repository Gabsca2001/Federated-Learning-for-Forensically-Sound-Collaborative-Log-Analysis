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

The maintained documentation was last reviewed on **13 November 2026**. The
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
| Admission gates, trigger probes, clipping and global rollback | [Gate research summary](docs/records/GATE_RESEARCH_HANDOFF.md) |
| Transfer to UNSW-NB15 and multi-source federation | [External-dataset studies](results/README.md#external-dataset-studies-november-2026) |
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
paths are protected. `make experiments` lists the targets that re-run the
completed studies (M4–M8 reference chain, gate and probe studies, external
datasets, M6 replays); a
campaign starts only when its target is named, and no target acquires
timestamps or modifies the manuscript.

## Evidence and interpretation

V5 separates utility risk from repeated update-magnitude anomalies. On the fixed
14-history assessment, selected benign memberships fall from eight to zero,
while selected adversarial memberships fall from 24 to 22. All six effective raw
attack cases have complete selected groups and exact same-excluded-roster clean
recovery after full-origin retraining. Remaining misses and ineffective
norm-limited controls prevent a general automatic-exclusion claim.

The November 2026 gate studies on Data24 add three live results that held under their predeclared protocols, each with stated limits. Per-tensor clipping contains scaled adaptive attacks. A per-key normalised trigger probe removes distributed backdoors (DBA) in IID and non-IID partitions without excluding honest clients. A global-model probe with rollback cuts the adaptive attacker's peak, but learning stalls while the attack lasts. Geometric head gates were stopped because their false positives stuck to particular honest clients, and the probe-aware attacker study could not be scored because both probe arms failed the clean guard. The probe and the rollback are now opt-in nodes of the signed derivation graph; in the swtpm live case the rollback never triggered, so that path is covered by unit tests only.

The V5 results concern retrospective analysis. Earlier positive containment cases,
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
| `docs/` | Maintained guide at the top; versioned references grouped in `milestones/`, `admission-gates/`, `formal/`, `measurement/`, `witness-chain/` and `records/` |
| `results/` | Study publications grouped in `milestones/`, `admission/`, `gates-probes/`, `chain-witness/`, `external-data/` and `records/`, plus the complete catalogue |
| `artifacts/` | Local runtime evidence, trust state and preserved releases |
| `data/` | Controlled local dataset inputs |

Many local research files have not been committed. Catalogue membership is not a
claim that an artifact is tracked, sanitized for public release or independently
authenticated. Historical evidence keeps its original bytes. The folders were
regrouped by theme on 13 November 2026; every move is listed in
[`results/records/relocation-20261113.json`](results/records/relocation-20261113.json),
and paths written inside frozen evidence still use the old layout. Large completed-study
evidence lives on an external disk ([offload record](docs/records/ARTIFACT_OFFLOAD.md)). The
[maintenance policy](docs/guide/MAINTENANCE.md) defines the documentation boundary.
