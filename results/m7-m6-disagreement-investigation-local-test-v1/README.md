# Verified M7 investigation of the M6 disagreement checkpoint

This sanitized snapshot reports the deterministic 16-case M7 investigation bound to
M6 campaign `campaign-cdf764235033c2ea022c9a75`, selected round `11`, and global
model `f0f430733f6dc6ff224c7fb98721517aff5e11d1311c8eb8913c86569cc7c681`. The complete source bundles remain under `artifacts/`
and are intended for M8 preservation; this directory publishes only bounded derived fields.

## Verified chain

- prediction bundle: `m7-prediction-bundle-0fb78b2c186b984ebcaacdaf`;
- explanation bundle: `m7-explanation-bundle-e8efef6beaf5876d1cdcbf8b`;
- ATT&CK mapping bundle: `m7-attack-mapping-bundle-e72b7e1b245643ce29a55faa`;
- investigation report: `m7-investigation-report-bundle-00689df47659e974273b1aae`;
- complete primary-evidence lineage: `811` normalized events
  and `826` controlled-ingestion source records;
- source manifest and artifact digests are recorded in `summary.json` and `manifest.json`.

The prediction bundle selected the first `16` test window identifiers in lexicographic
order. Selection used no label, prediction, confidence, or metric. The bundle produced
`15/16` correct evaluation outcomes (`93.8%`), but this
small fixed case set is an investigative demonstration and **not** a model-performance estimate.
Population-level test performance remains the isolated M6 evaluation.

## Explanation result

Integrated Gradients explained all `16` cases across
`25` features. Maximum absolute completeness error was
`0.000792027`,
below the configured `0.001` threshold. The five largest features by mean absolute attribution
were `unique_destination_port_count` (0.8486), `state_rej_fraction` (0.6483), `service_dns_fraction` (0.5010), `protocol_tcp_fraction` (0.4728), `protocol_udp_fraction` (0.4705).

The predicted class matched the nearest training-only prototype in
`11/16` cases (`68.8%`). Distances and
margins are model-geometry measurements; no row embeddings or global prototype vectors are
published here.

## ATT&CK result

MITRE ATT&CK Enterprise v19.2 produced
`5` candidate-tactic cases,
`4` benign/not-applicable cases, and
`7` deliberately unresolved multi-tactic cases.
The rule uses only the predicted class. Reference labels, Integrated Gradients, prototype
distances, and dataset ATT&CK annotations are excluded from rule selection. Technique-level
claims remain disabled.

## Files

- `summary.json`: compact source bindings, counts, descriptive measurements, and boundaries;
- `cases.csv`: one sanitized row per fixed case, including evaluation-only label and model/XAI
  summaries;
- `feature-attributions.csv`: aggregate attribution statistics for all 25 features;
- `prototype-summary.csv`: per-case nearest-prototype geometry without embeddings;
- `attack-mappings.csv`: per-case tactic status and rule, without source-record detail;
- `prediction-outcomes.png`: count matrix for the fixed selection, explicitly not a performance
  estimate;
- `feature-attributions.png`: ten largest mean absolute IG attributions;
- `prototype-distances.png`: nearest distance and separation margin;
- `attack-mapping-outcomes.png`: candidate, not-applicable, and unresolved counts;
- `manifest.json`: SHA-256 inventory of every published file and source-manifest bindings.

## Interpretation and disclosure boundary

Integrated Gradients and prototype geometry explain model behaviour; they do not establish
causality or malicious intent. ATT&CK entries are investigative hypotheses, not primary evidence.
`cases.csv` includes reference labels only for post-selection evaluation and labels that role
explicitly. This snapshot excludes source paths and row numbers, raw Zeek data, complete lineage
records, scaled input vectors, logits and probability vectors, model parameters, prototype
vectors, row embeddings, client updates, and private trust material.
