# Incremental implementation plan

Each milestone ends with an executable acceptance gate. A later milestone may add fields or artifact types, but it must not silently rewrite previously preserved objects.

| Milestone | Deliverable | Acceptance gate | Thesis requirements |
| --- | --- | --- | --- |
| M0 — Contract | Repository, configs, artifact schemas, architecture map | Configuration and schemas load; status is explicit | SIC6, FOR5, ML2 |
| M1 — Evidence vertical slice | Acquisition, hash chain, ECDSA, signed attestation result, admission, content-addressed vault, custody chain, deterministic snapshot | Tampering, wrong identity, expired attestation, chain conflict, and raw/snapshot separation are tested | SIC1–SIC5, FOR1–FOR5 |
| M2 — Data and centralized baseline | UWF-ZeekData22 inventory, group/time split, frozen feature schema, scaler fitted on training only, MLP encoder+head | Repeated preprocessing yields the same digest; centralized metrics include macro-F1 and per-class recall | ML2–ML4, ML8 |
| M3 — Federated baseline | 15 logical clients, IID/non-IID manifests, Flower ClientApp/ServerApp, FedAvg, round audit, model registry | No raw client mount at server; same frozen snapshots support local and FedAvg comparisons | ML1, ML3, ML4, FOR6 |
| M4 — Trust deployment | 15 `swtpm` pairs, enrollment, AK/ESK separation, Quote verification, mTLS, physical TPM adapter | Nonce replay, altered measurement, revoked identity, and wrong pair are rejected and preserved | SIC1–SIC6, FOR1–FOR4 |
| M5 — Secure round protocol | Signed round context and Update Bundles, replay/idempotency checks, structural validator, checkpoint manifests | Wrong round/base model/snapshot/tensor is rejected; every checkpoint lists actual inputs | SIC4, SIC7, FOR6, FOR8 |
| M6 — Byzantine experiments | Label flip, Gaussian noise, sign flip, model replacement, backdoor, prototype poisoning, collusion; clipping and robust aggregators | Same frozen updates feed FedAvg, median, trimmed mean, MultiKrum, Bulyan; invalid `n,f` halts explicitly | ML5–ML8, T1–T4 |
| M7 — Investigation | Inference bundles, Integrated Gradients, prototype distances, ATT&CK mapping, deterministic report | A prediction is reportable only with complete, digest-valid lineage to Zeek events | FOR6, FOR9, FOR10, ML9 |
| M8 — Campaign and recovery | Experiment manifests, repeated seeds, contamination propagation, rollback branch, root anchoring, export | Invariants have zero violations; statistical results include dispersion and confidence intervals | SIC8, FOR2–FOR10 |

The optional secure-aggregation profile is evaluated only after M6 because it conflicts with defenses that require inspection of individual updates. Optional DP-SGD is outside the core acceptance path and must not delay the thesis experiments.

