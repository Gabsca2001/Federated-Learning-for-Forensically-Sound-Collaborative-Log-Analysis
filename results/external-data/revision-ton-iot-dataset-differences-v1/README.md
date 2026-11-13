# Data24 vs ToN-IoT: dataset differences, feature shift and mapped subsets

Prepared on 10 November 2026 in response to the supervisor's request to *track and
discuss the differences* between the reference dataset (UWF-ZeekData24) and the
independent dataset (ToN-IoT network). Purely descriptive: no model is trained and
no p-values are reported, because windows are temporally correlated.

Evidence in this folder:

- `dataset-differences.json`: per-feature KS statistic, quantiles and out-of-envelope
  fractions, overall and within comparable label groups
  (`scripts/ton_iot_dataset_differences.py`);
- `mapped-subsets.json`: frozen Data24 six-class predictions on ToN-IoT subsets with
  an explicit label correspondence (`scripts/ton_iot_mapped_subsets.py`, reusing the
  retained frozen-transfer predictions, no new inference).

## 1. Source and labelling differences

| Aspect | UWF-ZeekData24 (reference) | ToN-IoT network (independent) |
| --- | --- | --- |
| Publisher | University of West Florida | UNSW Canberra |
| Release used | Parquet, 7 source partitions, 1,916,757 rows → 1,897,812 unique events | 23 processed CSVs, 22,339,021 rows; 869 malformed normal rows excluded |
| Capture period | 2024 (temporal holdout from 3 Nov 2024) | ten dates in April 2019 |
| Label semantics | MITRE ATT&CK tactics; windows with several tactics → `multi_tactic` | binary normal/attack plus ten source types (scanning, dos, ddos, injection, password, xss, ransomware, backdoor, mitm) |
| Labels used here | six classes | binary only; two explicit type → tactic correspondences (Section 4) |
| Connection identity | `uid` and event identities available | `uid` only in 1 of 23 files; 1.79M exact-field duplicate occurrences, kept as a sensitivity view |
| Service field | identified services | 16.9M records with unidentified service → `service_other_fraction` |
| Windows (60 s) | 19,576 in the reference snapshot (7,455 benign) | 7,934 (2,888 benign, 5,046 attack) |
| Benign/attack co-occurrence | benign-only and attack-present dates separated by design | many attack minutes also contain normal rows; several dates have no wholly benign window |

The 25-feature contract is reconstructed field by field (see
`results/external-data/revision-ton-iot-preflight-v1`). Payload bytes map to originator/responder
bytes; destination port zero is excluded from the distinct-port count as in Data24.

## 2. Feature shift by group (KS statistic, Data24 vs ToN-IoT)

| Feature group | All windows (mean / max KS) | Benign vs benign | Attack vs attack |
| --- | --- | --- | --- |
| Volume counts | 0.46 / 0.57 | **0.81** / 0.92 | 0.69 / 0.89 |
| Ports / destinations | **0.72** / 0.93 | 0.60 / 0.86 | **0.93** / 0.99 |
| Durations | 0.37 / 0.52 | 0.44 / 0.45 | 0.53 / 0.64 |
| Protocol fractions | 0.37 / 0.62 | 0.65 / **1.00** | 0.52 / 1.00 |
| Service fractions | 0.34 / 0.62 | 0.45 / **1.00** | 0.42 / 0.99 |
| State fractions | 0.34 / 0.66 | 0.40 / 0.99 | 0.35 / 0.53 |

Selected medians (Data24 → ToN-IoT):

| Feature | Benign | Attack |
| --- | --- | --- |
| `unique_destination_port_count` | 2 → 8 (90% of ToN-IoT benign outside the Data24 training 0.5–99.5% envelope) | 1 → 12 (97.5% outside) |
| `connection_count` | 116 → 65 | 6 → 2,217 |
| `protocol_tcp_fraction` | 0.07 → 0.63 | 1.00 → 0.96 |
| `service_dns_fraction` | 0.92 → 0.22 | 0.00 → 0.02 |
| `state_sf_fraction` | 0.75 → 0.00 | 0.61 → 0.09 |

## 3. Reading

1. **Even benign traffic differs completely.** Data24 benign minutes are dominated by
   DNS over UDP with completed (`SF`) connections; ToN-IoT benign minutes are mostly
   TCP with almost no `SF` state. KS is close to 1 for protocol, DNS and `SF` shares.
   The two benign populations come from different networks and capture conditions,
   so equal labels do not imply comparable traffic.
2. **The distinct-port count is the clearest scale break.** In Data24, attack minutes
   typically reach one destination port, while ToN-IoT benign minutes already reach
   eight. Ninety per cent of ToN-IoT benign windows fall outside the Data24 training
   envelope on this feature. This is consistent with the robust-transfer ablation, where
   removing the ports/destinations group raised mean balanced accuracy by 0.15 and
   lowered the false-positive rate by 0.32 (`artifacts/ton-iot-robust-transfer-v1`).
3. **Attack intensity differs by orders of magnitude.** ToN-IoT attack minutes contain a
   median of 2,217 connections against six in Data24, reflecting DoS/DDoS/scanning
   campaigns in a laboratory testbed rather than low-volume tactic steps.
4. **Consequence for transfer.** The shift is not a single rescaling of heavy-tailed
   counts: proportions (protocol, service, state) also move to the edge of their range.
   This explains why the Data22-derived `counts-only` correction does not transfer to
   ToN-IoT, while `proportions-only` and the ports ablation partially recover (observed
   after the fact, not selected by Data24 validation).

## 4. Explicitly mapped subsets

Declared correspondences: `scanning → reconnaissance`, `password → credential_access`.
A window enters a subset when its only non-normal source type is the mapped one.

| ToN-IoT type | Windows | Predicted as mapped tactic | Predicted non-benign | Most frequent prediction |
| --- | ---: | ---: | ---: | --- |
| scanning | 243 (11 without normal rows) | 0 | 99.6% | `multi_tactic` (240) |
| password | 842 (0 without normal rows) | 0 | 100% | `multi_tactic` (842) |
| benign windows (reference) | 2,888 | – | 99.7% | `multi_tactic` (2,878) |

The frozen model maps almost every ToN-IoT window, benign included, to `multi_tactic`.
Non-benign rates on mapped subsets therefore carry no tactic-level information, and
the mapped-tactic recall is zero for both correspondences. The other ToN-IoT types
(dos, ddos, injection, xss, ransomware, backdoor, mitm) have no explicit counterpart in
the six Data24 classes and are evaluated only in the binary view.

## Limits

- Descriptive statistics on correlated windows; KS values are not significance tests.
- Data24 quantiles use all reference-snapshot windows of each label; the out-of-envelope
  fractions use the Data24 training split (sampled as in the snapshot).
- Mapped subsets mix normal rows within the minute; only 11 scanning windows are pure.
- The type → tactic correspondences are a declared modelling choice, not part of either
  release.
