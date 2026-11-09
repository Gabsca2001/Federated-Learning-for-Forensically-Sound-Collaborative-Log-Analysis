# Glossary

Short definitions of the identifiers used across the maintained guide, the
study reports and the thesis. Exact contracts remain in the referenced
formal and protocol documents.

## Pipeline stages

| Term | Meaning |
| --- | --- |
| M1 | Separate acquisition and artifact-contract demonstration; Data24 is not retrospectively attested through it |
| M2 | Controlled Data24 ingestion, normalization, feature windows, splits and scaler |
| M3 | Client partitions (IID and non-IID) and clean centralized, federated and local-only baselines |
| M4 | Client identity, key separation, enrollment and software-TPM attestation |
| M5 | Secure federated rounds: signed bundles, context checks, admission and checkpoints |
| M6 | Byzantine attacks, admission policies and robust aggregation comparisons |
| M7 | Investigative products: predictions, explanations, candidate ATT&CK mappings and reports |
| M8 | Preservation, inventory, timestamping and offline recovery |

## Derivation and accounting

| Term | Meaning |
| --- | --- |
| Provenance | Recorded dependency of an artifact on its inputs, independent of numerical weight |
| Mandatory gate | Conjunction of identity, signature, context, structure, replay and attestation checks; a failed gate gives zero mass |
| Effective mass | Example count multiplied by the policy factor (1 for accept, a fixed factor for downweight, 0 otherwise) |
| Coefficient | Effective mass normalized over the positive-mass contributors of one round |
| Scoring population | Committed set of eligible updates used to compute statistics before actions are decided |
| Semantic review | Signed, append-only judgment about a submission; it never rewrites the historical round |
| Receipt | Client-signed binding of campaign, client, round, base model and bundle digest, used to check inventory coverage |
| Blast radius | Artifacts reachable from a submission through numerical, decision and audit edges; an investigation scope, not a damage measurement |

## Experimental vocabulary

| Term | Meaning |
| --- | --- |
| Profile | Named, versioned configuration with its own contract, evidence and verifier |
| Contract | Declared inputs, operations and outputs that a verifier checks for a profile |
| Common-input comparison | Several server rules applied to the same incoming base and updates; outputs are immediate responses, not independently evolving defended histories |
| Information budget | Data and state available to a defense, such as auxiliary samples, clean references or gradient history |
| Effective case | Attack history whose undefended raw run meets the study's predeclared effectiveness threshold |
| Full-origin replay | Retraining from the preserved pre-attack checkpoint under a declared removal schedule, so later clients train from corrected parents |
| Same-roster clean reference | Clean history that excludes the same clients as the intervention branch |
| V4, V5 | Retrospective group selectors; V5 separates utility risk from repeated update-magnitude episodes |
| DBA | Distributed backdoor attack: trigger components assigned to different colluding identities |
| ASR | Attack success rate on the declared trigger evaluation set |
