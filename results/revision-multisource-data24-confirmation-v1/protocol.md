# Protocol: confirmation of multi-source view A on held-out Data24 (v1)

Written 2026-11-10 before running this configuration with the seeds below. SHA-256 in
`protocol.sha256`; the script refuses to run if it differs.

## Hypothesis (from `scripts/explore_multisource_two_view.py`, seeds 0–2)

A FedAvg classifier trained on Data22, ToN-IoT and UNSW-NB15 only (three clients, each
expressing units as deviations from its own benign baseline, input view A
`[clip(z, ±20), log1p|z|]`) detects Data24 attacks without any Data24 label. Exploratory
result: BA 0.974, recall 0.82 at 0.1% FPR; a single source (UNSW-NB15) was at chance.

## Frozen configuration

Exactly as in the exploratory run: `multisource_fl.load_domains()` domains and baselines;
view A; 50→128→64→32 encoder + binary head; FedAvg over the three clients (sample-weighted),
30 rounds, 2 local epochs, Adam 1e-3, batch 128, class-balanced loss, final round; score =
logit margin; baseline rank; 5-unit trailing median over Data24 windows in time (single
entity, restart after gaps > 10 min); alert above the 99th percentile on the Data24 baseline.

**New seeds: 3, 4, 5, 6, 7** (0–2 were used in exploration). Evaluated per seed.

Data24 baseline: benign windows of the train and validation splits (as in all multi-source
runs). Test: Data24 `split == test` (4,937 windows). Reference arm, same seeds: single source
UNSW-NB15.

## Criteria (mean over the five seeds)

**Confirmed** if all hold: (1) BA ≥ 0.90; (2) recall at 0.1% test FPR ≥ 0.50; (3) at least
four of five seeds with BA ≥ 0.85; (4) multi-source BA − single-source BA ≥ 0.20.
**Not confirmed** if BA < 0.75. **Partial** otherwise.

## Limits declared in advance

Data24 splits are chronological with benign-only and attack-present date regimes, so
benign and attack test windows are not fully contemporaneous; the Data24 baseline is
selected by split/benign regime; numerical FedAvg without the secure pipeline; the
multi-source design and view A were chosen while looking at the three source datasets.
