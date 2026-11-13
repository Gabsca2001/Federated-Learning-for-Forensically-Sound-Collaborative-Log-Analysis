# Official ToN-IoT network preflight

The full official processed network release was acquired from the publicly
linked UNSW SharePoint collection and all **22,339,021 CSV occurrences across
23 files** were scanned. Counts for every one of the ten published classes
match the official network statistics exactly. Every field needed by the
existing 25-feature representation is available. This publication establishes
source coverage and a record-mapping preflight; model transfer and retraining
have not been evaluated.

## Findings and preparation decisions

| Finding | Evidence and consequence |
| --- | --- |
| Official collection coverage | 23 indexed CSVs, locally pinned source hashes and exact agreement with the official ten-class counts |
| Header variation | File 6 includes `uid`; the other 22 have no `uid`. Readers align columns by name |
| Invalid source occurrences | 869 records contain invalid source-IP and payload-byte values. Exact file, source hash, record number and reasons are retained in the proposed-rejection ledger |
| Rejection population | All 869 flagged records carry the normal label. They are 0.00389% of all records and about 0.109% of normal records |
| Unknown service | 16,909,396 records contain an unidentified service. These are retained as `missing`, contributing to the existing `service_other_fraction` |
| Required numeric observations | No missing duration, packet or payload-byte measurements were found; malformed byte values are reported separately |
| File boundaries | 22 occupied 60-second buckets span multiple files, requiring a global merge before aggregation |
| Labels | No binary/type conflicts were found. Binary normal/attack labels and source attack types remain separate from MITRE classes |
| Tests | 26 focused checks passed, including the existing single-file preflight tests and direct checks against the real 25-feature window function |

`collection-preflight.json` records source hashes, all row counts, missing and
invalid fields, timestamps, category values and proposed rejection coordinates.
`proposed-rejected-occurrences.json` retains selected original values and checks
that the strict adapter rejects each flagged occurrence. Its rows describe a
preparation decision, not deletion from the source dataset. Source bytes remain
unchanged and no derived feature dataset has been materialized.

## Representation correspondence

The adapter maps source/destination payload bytes to the originator/responder
payload-byte inputs. IP-level byte counters are not substituted. Protocols,
services and states follow the existing category normalization and complement
rules. A missing service contributes to `other`; it does not remove a connection
or introduce a numeric zero measurement. Malformed numeric values are rejected
with an identifiable source occurrence instead of being repaired by inference.

Window grouping follows the existing Data24 implementation: capture day and
`floor(ts/60)`. ToN-IoT capture days are derived from the seconds epoch in UTC,
and all source-file fragments are merged. Introducing a per-source-IP grouping
would change the training representation. Population standard deviation and
the existing exclusion of destination port zero from the distinct-port count
are retained.

| Existing feature | Official source fields | Operation |
| --- | --- | --- |
| `connection_count` | `ts` | Count every retained event in the global capture-day/60-second bucket. |
| `unique_destination_count` | `dst_ip` | Count distinct nonempty destination IP values. |
| `unique_destination_port_count` | `dst_port` | Count distinct nonzero destination ports, matching the existing implementation. |
| `duration_mean` | `duration` | Arithmetic mean in seconds. |
| `duration_std` | `duration` | Population standard deviation in seconds. |
| `duration_max` | `duration` | Maximum duration in seconds. |
| `originator_bytes_sum` | `src_bytes` | Sum the corresponding connection-level payload bytes or packet counts. |
| `responder_bytes_sum` | `dst_bytes` | Sum the corresponding connection-level payload bytes or packet counts. |
| `originator_packets_sum` | `src_pkts` | Sum the corresponding connection-level payload bytes or packet counts. |
| `responder_packets_sum` | `dst_pkts` | Sum the corresponding connection-level payload bytes or packet counts. |
| `protocol_tcp_fraction` | `proto` | Fraction of all retained connections in the named category; other is the complement of tcp/udp/icmp. |
| `protocol_udp_fraction` | `proto` | Fraction of all retained connections in the named category; other is the complement of tcp/udp/icmp. |
| `protocol_icmp_fraction` | `proto` | Fraction of all retained connections in the named category; other is the complement of tcp/udp/icmp. |
| `protocol_other_fraction` | `proto` | Fraction of all retained connections in the named category; other is the complement of tcp/udp/icmp. |
| `service_dns_fraction` | `service` | Fraction of all retained connections in the named category; other is the complement of dns/http/ssl/ssh. |
| `service_http_fraction` | `service` | Fraction of all retained connections in the named category; other is the complement of dns/http/ssl/ssh. |
| `service_ssl_fraction` | `service` | Fraction of all retained connections in the named category; other is the complement of dns/http/ssl/ssh. |
| `service_ssh_fraction` | `service` | Fraction of all retained connections in the named category; other is the complement of dns/http/ssl/ssh. |
| `service_other_fraction` | `service` | Fraction of all retained connections in the named category; other is the complement of dns/http/ssl/ssh. |
| `state_sf_fraction` | `conn_state` | Fraction of all retained connections in the named category; other is the complement of SF/S0/REJ/RSTO/RSTR. |
| `state_s0_fraction` | `conn_state` | Fraction of all retained connections in the named category; other is the complement of SF/S0/REJ/RSTO/RSTR. |
| `state_rej_fraction` | `conn_state` | Fraction of all retained connections in the named category; other is the complement of SF/S0/REJ/RSTO/RSTR. |
| `state_rsto_fraction` | `conn_state` | Fraction of all retained connections in the named category; other is the complement of SF/S0/REJ/RSTO/RSTR. |
| `state_rstr_fraction` | `conn_state` | Fraction of all retained connections in the named category; other is the complement of SF/S0/REJ/RSTO/RSTR. |
| `state_other_fraction` | `conn_state` | Fraction of all retained connections in the named category; other is the complement of SF/S0/REJ/RSTO/RSTR. |

## Temporal and evaluation implications

Before any rejection, the release occupies 7,934 global one-minute buckets:
2,888 contain only normal rows, 123 only attack rows and 4,923 contain both.
The flagged occurrences intersect 247 buckets. These are pre-preparation
diagnostics; they are not the size or class balance of a finalized window
dataset. Source-IP, timestamp and byte anomalies remain visible in the ledger.

At record level, predicting attack for every row would obtain approximately
96.44% accuracy because attack records dominate. That is a constant-label
arithmetic baseline, not a model result. Model evaluation must report the
relevant unit, normal-class performance, attack recall, false positives and
balanced metrics, including the window-label rule and confusion matrix.

The first three observed dates contain only normal records, while later dates
contain both binary classes. Split construction therefore needs explicit
temporal/group support checks. Randomly splitting CSV chunks would fail to
control the shared-window boundary. ToN-IoT labels must not be used to retune a
model reported as frozen Data24 transfer.

## Scope and next validation

The source-statistics match concerns the complete processed release, which the
publisher describes as filtered data. It does not establish reconstruction of
every raw capture event. CSV occurrence IDs are retained separately from unique
connection identities: `uid` is absent from most files and exact duplicate or
join-multiplicity assessment has not yet been performed. No distinct-connection
count is claimed. Occurrence-based counting or consolidation must be declared
and assessed before asserting final representation equivalence.

The next validation freezes the occurrence/connection policy, derives globally
merged windows with explicit rejected-input accounting and tests the frozen
Data24 model with its retained scaler and declared binary decision rule.
Separate ToN-IoT retraining can then distinguish transfer failure from a
limitation of the representation. Full dataset compatibility, model accuracy
and generalization are not established by this preflight. The thesis and
existing training artifacts have not been changed.

## Retained evidence and reproduction

- `acquisition-index.json` locates nine valid CSV entries inside the original
  provider ZIP and fourteen standalone official CSVs. No duplicate extraction
  is required. The provider ZIP remains incomplete on its own.
- `official-network-statistics.txt` and `official-feature-description.txt` are
  text extractions of official documentation. Their original document URLs,
  byte lengths and SHA-256 digests appear in `official-description-manifest.json`.
- `sources/` pins the adapter, collection scanner and focused test files used
  for this publication. `tests.log` records the 26 focused passes, not a new
  full-suite result.
- `file-checksums.json` supports stored-publication checks through the repository
  catalogue. Local checksums pin retained bytes and do not constitute
  publisher-issued checksum attestations or independent trust certification.

From the Linux/WSL repository root, run `make test-ton-iot`. Repeating the full
record scan requires the acquired source files and an explicit source index:

```bash
make ton-iot-preflight \
  TON_IOT_INDEX=/mnt/c/Users/scama/Downloads/ToN-IoT-official/collection-complete.json \
  TON_IOT_OUTPUT=artifacts/ton-iot-preflight-new
make evidence-check STUDY=results/external-data/revision-ton-iot-preflight-v1
```

The preflight target refuses an existing output path and does not download,
extract, train or modify the thesis.

## Primary sources

The [official UNSW project page](https://research.unsw.edu.au/projects/toniot-datasets)
distinguishes processed releases, sampled training/test data and feature
documentation. The acquired network documentation identifies endpoint roles,
payload bytes, packet counts, connection state and binary labels. The
[Zeek connection schema](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html)
provides the underlying connection-field semantics. Citation and dataset-use
requirements remain those stated by the publisher.
