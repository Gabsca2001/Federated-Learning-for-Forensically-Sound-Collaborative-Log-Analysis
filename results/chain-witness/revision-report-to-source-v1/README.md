# Report-to-source walkthrough: m7-investigation-case-498ee95ed92e641b997528a6

This folder walks one M7 case from the published investigation report back to
the six Data24 Parquet rows the report references. It then evaluates the report's
reconnaissance hypothesis against criteria frozen in advance in `protocol.md`.

| File | Role |
|---|---|
| `protocol.md` | Criteria, written before the walkthrough read the rows |
| `protocol.sha256` | SHA-256 of `protocol.md` (`4ffb783a3bb1a843557c6aaea0e07a2157205b52f66773ff9524c9035a3b26a9`); the script checks it before reading any row |
| `walkthrough.json` | Output of `scripts/report_to_source_walkthrough.py` |

The rows are read with the existing reader
`src/fl_forensics/dataset24_parquet.py:187-202` (`_iter_parquet_rows`, numbering
from 1). Digests are recomputed with `fl_forensics.dataset24._full_row_digest`
and `_identity_digest`. Tests are in `tests/test_report_to_source_walkthrough.py`.

Reproduce:

```bash
.venv/bin/python scripts/report_to_source_walkthrough.py --overwrite
.venv/bin/python -m pytest -q tests/test_report_to_source_walkthrough.py
```

## 1. Verified (digests)

- `m7/investigation-report.json` and `m7/report.md` match
  `core.investigation_report_sha256` and `core.report_markdown_sha256` in
  `m7/manifest.json`.
- The canonical core recomputes to `fe23c60b…45ca` and equals
  `canonical_core_sha256`. The bundle id carries the same prefix. The core is
  serialized with the report builder's own `_canonical_json_bytes`
  (`investigation_report.py:68`, with a trailing newline). A first attempt with
  the generic `fl_forensics.canonical` serializer gave a different value
  (`3ed0ca2e…`); that was a serializer mismatch in the walkthrough script, not
  in the manifest.
- Source file: `2024-03-17 - 2024-03-24/part-00000-5f556208-…-c000.snappy.parquet`,
  27 802 118 B, SHA-256 `97dda852…9f63`. It matches the report and the dataset
  `download_manifest.json`.
- 6/6 `source_record_sha256` (all 26 columns) and 6/6 `source_identity_sha256`
  (label columns excluded) recompute exactly from rows 64274, 73452, 73715,
  175166, 323166 and 323200.

This verifies integrity and attribution only: these are the bytes the report
points to. It does not establish what the traffic means.

## 2. Observed (raw fields, labels not extracted)

| row | dst IP | dst port | proto | service | conn_state | history | orig/resp bytes | orig/resp pkts | duration (s) | time (UTC) |
|---:|---|---:|---|---|---|---|---|---|---:|---|
| 64274 | 143.88.8.10 | 135 | tcp | – | S0 | S | 0/0 | 4/0 | 0.00137 | 23:23:30.818 |
| 73452 | 143.88.8.1 | 135 | tcp | – | S0 | S | 0/0 | 3/0 | 0.00061 | 23:23:30.918 |
| 73715 | 143.88.8.1 | 135 | tcp | – | S0 | S | 0/0 | 3/0 | 0.00104 | 23:23:30.818 |
| 175166 | 143.88.8.10 | 135 | tcp | – | S0 | S | 0/0 | 4/0 | 0.00203 | 23:23:30.918 |
| 323166 | 143.88.8.11 | 135 | tcp | – | REJ | Sr | 0/0 | 4/4 | 0.00235 | 23:23:30.818 |
| 323200 | 143.88.8.12 | 135 | tcp | – | REJ | Sr | 0/0 | 4/4 | 0.00245 | 23:23:30.818 |

Descriptive summary:
- There is one originator, `143.88.7.11`.
- It contacts 4 distinct destination IPs, all on 1 port (TCP 135). Two
  destinations appear twice.
- Connection states are 4 S0 (SYN with no reply) and 2 REJ (SYN answered
  with RST). There are 0 established connections.
- Application payload is 0 bytes in every record. Packets total 22 originator
  and 8 responder.
- Durations range from 0.6 to 2.4 ms. All 6 records fall within a 0.1 s span on
  2024-03-22.

Secondary consistency check (protocol §5, not part of the verdict):
- The report's top IG features are `state_rej_fraction`, `state_s0_fraction`,
  `service_other_fraction`, `state_sf_fraction` and `unique_destination_count`.
- In the records there are 2 REJ, 4 S0, 0 SF, an empty `service` in all 6
  records, and 4 distinct destinations. This walkthrough does not establish how
  the empty service maps to `service_other_fraction`.
- The features named by IG correspond to properties visibly present (or, for
  SF, absent) in the rows. This is not a test of attribution fidelity.

## 3. Hypothesis

The report (Analyst Summary for this case) states that the model classified the
window as Reconnaissance, with a confidence of 76.52%. It also states that,
under the frozen ATT&CK v19.2 policy, "the prediction supports the
investigative tactic hypothesis **TA0043 — Reconnaissance**", with no
technique-level claim.

The protocol tests a narrower statement: whether the referenced records show a
network pattern compatible with reconnaissance-style probing. It does not test
whether the activity was malicious.

## 4. Conclusion

Verdict under the frozen protocol: **supported**.

- S1: holds, with a single originator.
- S2: holds, with fan-out over 4 destination IPs. The port fan-out is 1.
- S3: holds, with 6/6 records unestablished or rejected.
- S4: holds, with zero payload.
- S5: holds, with a span of 0.1 s.
- None of C1–C3 holds.

What this means:
- The referenced source records are *compatible* with a short probe of TCP 135
  (MS-RPC endpoint mapper) by one host across four addresses. They are
  consistent with the IG features the report names.
- This does **not** confirm malicious activity, intent, an actor, an ATT&CK
  technique, or that the dataset's ground truth is correct. Authorised scanners,
  service discovery, monitoring or misconfiguration can produce the same six
  records.
- The criteria are descriptive heuristics with no calibration or error rate.

Limits:
- **No study with independent analysts was performed.** The same agent wrote
  the criteria, the script and this conclusion.
- **Prior exposure:** before `protocol.md` was written, an earlier read-only
  step in the same session had already printed `label_tactic`, `datetime`,
  `src_ip_zeek`, `dest_ip_zeek` and `conn_state` for these rows (see
  protocol §6). S1, the IP part of S2, S3 and S5 were therefore set after
  partial exposure. The port, byte, packet, duration, service and history fields
  (which feed S4 and the C conditions) had not been seen. This weakens the
  independence of the verdict, and the verdict should be weighed accordingly.
- The case contains only 6 records from one window. The verdict concerns this
  case only and says nothing about other M7 cases or about the model's
  reliability.
- Dataset label columns were not extracted and not used. They enter only the
  digest recomputation, as opaque bytes.
- The M2/M3 lineage digests (`lineage_record_sha256`, window row hashes) were
  not recomputed here. The walkthrough verifies report → manifest → source
  file → source rows, not the intermediate window derivation.
- The manifest records `global_model_sha256` `007e3faf…`, the historical
  checkpoint whose bytes do not match the currently retained round-11 model
  (see `results/external-data/revision-ton-iot-transfer-v1/README.md:134-144`). This does not
  affect the source-row verification above, but it means this case cannot be
  re-scored with a checkpoint verified to be the same.
