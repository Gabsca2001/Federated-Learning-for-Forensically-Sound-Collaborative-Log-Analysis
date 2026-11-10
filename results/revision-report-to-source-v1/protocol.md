# Protocol: report-to-source walkthrough for m7-investigation-case-498ee95ed92e641b997528a6

Status: frozen before the walkthrough script reads the six source rows.
Its SHA-256 is recorded separately in `protocol.sha256`.
These criteria are descriptive, not calibrated. They have no error rate, they are
not validated against analysts, and they must not be edited after the rows are read.

## 1. Hypothesis under evaluation (quoted from the report)

Source: `results/reference-local-test-v1/m7/report.md`, section
"Case m7-investigation-case-498ee95ed92e641b997528a6", Analyst Summary:

> The federated model classified the analyzed network window as **Reconnaissance**,
> with a confidence score of **76.52%**. [...] Under the frozen MITRE ATT&CK
> Enterprise v19.2 mapping policy, the prediction supports the investigative tactic
> hypothesis **TA0043 — Reconnaissance**. No technique-level claim is made
> automatically.

The Evidentiary Assessment states that model outputs "do not independently
establish that the hypothesized attack activity occurred."

The hypothesis tested here is therefore restricted to the following statement:
*the referenced source records show a network-behaviour pattern compatible with
reconnaissance-style probing (one originator contacting several destinations
and/or ports with short, mostly unestablished or rejected, low-payload
connections).* Whether that activity was malicious, authorised or a benign scanner
is outside what six connection records can show, and it is not evaluated.

## 2. Evidence chain checks (preconditions)

- P1. The SHA-256 of `investigation-report.json` and of `report.md` equals
  `core.investigation_report_sha256` and `core.report_markdown_sha256` in
  `m7/manifest.json`.
- P2. The Parquet source file exists. Its size and SHA-256 equal the values the
  report declares and the values in the dataset download manifest.
- P3. For each of the 6 references, the row read at `row_number` with the
  existing reader (`src/fl_forensics/dataset24_parquet.py:187-202`, numbering from
  1) reproduces the declared `source_record_sha256`
  (`dataset24._full_row_digest` over all 26 columns). It must also reproduce
  `source_identity_sha256` (`dataset24._identity_digest`, label columns excluded).

If any of P1–P3 fails, the verdict is **inconclusive**: the evidence boundary
is broken and the rows cannot be attributed to the report.

## 3. Fields used

The verdict uses only the following fields: `src_ip_zeek`, `dest_ip_zeek`,
`dest_port_zeek`, `proto`, `service`, `conn_state`, `history`, `duration`,
`orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `datetime`.

The dataset label columns (`label_tactic`, `label_technique`, `label_binary`,
`label_cve`) are **not** extracted and **not** used. They are the training
ground truth, so using them would be circular. They enter only the digest
recomputation, as opaque bytes.

The following conn_state groups are fixed in advance (Zeek semantics):
- unestablished/rejected: `S0`, `REJ`, `RSTOS0`, `RSTRH`, `SH`, `SHR`, `OTH`
- established: `SF`, `S1`, `S2`, `S3`, `RSTO`, `RSTR`

Per-record payload is `orig_bytes + resp_bytes`, with an empty or missing value
counted as 0 and flagged.

## 4. Criteria

**Supported** if all of the following hold:
- S1. There is one distinct originator (`src_ip_zeek`) across all 6 records.
- S2. There is fan-out: at least 2 distinct destination IPs, or at least 2
  distinct destination ports.
- S3. At least 4 of the 6 records are in the unestablished/rejected group.
- S4. The median per-record payload is 0 bytes, and no record carries more
  than 1000 bytes of payload.
- S5. All records fall within a span of at most 60 seconds (the window
  length).

**Contested** if any of the following holds:
- C1. At least 4 of the 6 records are in the established group, with payload
  greater than 0 in both directions (ordinary service use).
- C2. Every record has the same destination IP and the same destination port,
  and the majority are established (no probing structure).
- C3. There are 2 or more distinct originators and no originator shows fan-out
  (the window mixes unrelated traffic rather than one probing source).

**Inconclusive** if:
- a precondition P1–P3 fails, or
- more than 2 records lack `conn_state` or the byte fields, or
- neither the full Supported set nor any Contested condition is met, or
- both a full Supported set and a Contested condition hold (this is logically
  unlikely, but it is resolved as inconclusive rather than by choosing one).

## 5. Secondary descriptive check (not part of the verdict)

The report's top Integrated Gradients features are `state_rej_fraction`,
`state_s0_fraction`, `service_other_fraction`, `state_sf_fraction` and
`unique_destination_count`. The walkthrough reports the raw counts of REJ, S0
and SF records, of service values, and of distinct destinations, so that a
reader can see whether those features correspond to something present in the
records. This is a consistency observation, not a test of attribution fidelity.

## 6. Limits declared in advance

- There are only 6 records, all from one 60-second window. The pattern
  criteria above are heuristics, and benign scanners, monitoring or
  misconfiguration can produce the same pattern.
- A "supported" verdict means *compatible pattern in the referenced records*.
  It does not confirm malicious activity, intent, actor or ATT&CK technique.
- No study with independent analysts was performed. These criteria were
  written by the same agent that runs the walkthrough.
- **Prior exposure disclosure:** in an earlier read-only reconnaissance in the
  same session (before this protocol was written), the 6 digests were already
  recomputed. During that step the following values were printed for these
  rows: `label_tactic`, `datetime`, `src_ip_zeek`, `dest_ip_zeek` and
  `conn_state`. The criteria were written after that partial exposure. Byte,
  port, duration, service, history and packet fields had not been seen. This
  limits the protocol's independence, and readers should weigh S1, S2 (IP part),
  S3 and S5 accordingly.
