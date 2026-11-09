# Authenticated coverage of ingested source occurrences

This profile implements the upstream coverage obligation in the original formal
proposal, separate from receipt-relative coverage of federated submissions.
It accounts for every source occurrence in pinned input files. It does not
certify that capture before this ingestion boundary was complete or truthful.

## Production and verification

`ingestion-create` freezes the declared source files, enumerates their record
occurrences, and writes `input-inventory.json` **before** calling the existing
transformation. It then produces a new snapshot, `record-outcomes.jsonl`, and a
signed `manifest.json`. Historical snapshots and campaign artifacts are not
rewritten. The new Data24 snapshot can be passed to the existing partitioning
pipeline as `WORKSPACE/snapshot`; preserve the surrounding ingestion evidence
alongside it when claiming record coverage. Ordinary legacy `m2-verify` remains
an artifact-integrity check and does not itself assert this stronger property.

The inventory authenticates the profile, source file hashes, configuration hash,
source-record stream hash, and record count. The final manifest authenticates
that exact inventory, the outcome stream, all snapshot files, outcome counts,
and the Python package fingerprint. The authority key and expected inventory
and final-manifest hashes must be trusted independently of the workspace.
The CLI accepts a source anchor from the caller: the raw-file byte hash for
JSONL, or the `download_manifest.json` **byte hash** for Data24. A canonical-core
digest of a download manifest is a different value and must not be substituted.

`ingestion-verify` verifies both signatures and pins, freezes copies of the
committed source bytes, re-enumerates I0, re-executes the transformation, and
reconstructs every outcome. It compares the reconstructed streams and payloads
with the signed commitments. Missing inventory, outcomes, sources, or snapshot
files fail verification; there is no fallback to a weaker coverage claim.
Verification does not write into the supplied evidence workspace.

## Record identities and outcomes

An identity commits to source path, position, profile-specific record digest,
and whether the occurrence is a blank data line. Equal values in different
positions remain different inputs. Inputs can share a consolidated event and
multiple events can share a feature window.

Supported profiles:

* `zeek-jsonl-v1`: each physical line yielded by `bytes.splitlines()` is an
  occurrence. A terminating newline does not create an extra record. The record
  digest excludes the line terminator, matching the existing normalizer.
  Empty data lines, invalid JSON, missing/invalid timestamps, missing labels,
  and invalid source-lineage fields receive explicit discard reasons.
* `data24-csv-v1`: the header declares the schema and is not a log event. Each
  subsequent physical data line is an occurrence, including blank lines.
  Digests retain the exact UTF-8 line representation and terminator used by the
  Data24 loader. Unsupported/malformed physical CSV rows make transformation
  fail; a successful coverage manifest is not fabricated for them.
* `data24-parquet-v1`: each row in every pinned source file is an occurrence.
  The row digest uses the existing Data24 canonical ordered string-column
  representation, bound to the original file bytes and pinned implementation.
  Taxonomy duplicates are retained as separate source references to the same
  consolidated event. Training-only selection exclusions have the explicit
  reason `training_window_not_selected`, with intermediate event/window IDs.
  Independent replay checks that the configured selection actually excludes
  those windows; arbitrary claimed discard reasons do not suffice.

For each input, exactly one terminal outcome is emitted: `derived`, linked to
an existing retained window and its event; or `discarded`, with its reason and
any intermediate event/window references. A disk-backed join checks unique
source references, their content digests, event existence, and membership in
the declared retained window. Extra or unaccounted source references fail.
The verifier compares identities and associations, not merely counts.

An empty committed input is checked as empty but reports
`nontrivial_coverage_verified=false`. No profile claims global capture
completeness, independent time certification, or that an inventory existed
before an earlier historical transformation. The implementation writes the
inventory before **this new replay**; independently proving chronology requires
an external witness or retained commitment. Signing a software-generated
manifest does not turn its authority into an independent witness.

## Example

```bash
fl-forensics ingestion-create \
  --workspace artifacts/new-data24-ingestion \
  --source data/raw/uwf-zeekdata24/parquet \
  --profile data24-parquet-v1 \
  --expected-source-sha256 "$TRUSTED_DOWNLOAD_MANIFEST_BYTE_HASH" \
  --config configs/m2-parquet.yaml \
  --authority-private-key private/analyst.private.pem \
  --authority-public-key trusted/analyst.public.pem

fl-forensics ingestion-verify \
  --workspace artifacts/new-data24-ingestion \
  --expected-inventory-sha256 "$RETAINED_INVENTORY_HASH" \
  --expected-manifest-sha256 "$RETAINED_COVERAGE_HASH" \
  --authority-public-key trusted/analyst.public.pem
```

The verifier deliberately requires the preserved Python release. Dependency
versions and parsing profiles are part of reproducibility assumptions. It
rechecks actual source and derived bytes; retaining only a report is not enough
to repeat full verification. Store private keys separately from public evidence.
