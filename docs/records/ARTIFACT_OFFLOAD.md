# Artifact offload to the external SSD

Started 2026-11-11 on operator request to free the system disk (C:). Completed-study
evidence is moved, verified, to the external SSD; everything needed by current and
future experiments stays in `artifacts/`.

## Where things are

* Archives: `D:\fl-artifacts-archive\<artifact>.tar.gz` (inside WSL: `/mnt/d/fl-artifacts-archive/`).
  One gzip tar per artifact (or per sub-path), created with paths relative to `artifacts/`.
* Manifest (one JSON line per archive, also copied on D:): [`results/records/artifact-offload/manifest.jsonl`](../../results/records/artifact-offload/manifest.jsonl)
  — artifact, kind, what stayed on C:, source bytes and entry count, archive path, size,
  SHA-256, verified entry count, restore command.
* Script: [`scripts/offload_artifacts.sh`](../../scripts/offload_artifacts.sh).

## Procedure per artifact

1. `tar -I pigz` archive written to D: (exFAT keeps no Linux symlinks/permissions; the
   archive does).
2. Verification: the archive is fully listed and its non-directory entry count must equal the
   source's; on any failure the item is skipped and nothing is deleted.
3. SHA-256 of the archive recorded; only then the source (or the declared sub-path) is removed.

## Batches

* **Attempt 0 (2026-11-11 15:54):** aborted. The USB SSD disconnected during the first
  archive (exFAT "delayed write failed"); every item failed before deletion, so no source
  was removed; the incomplete archive was deleted afterwards. The script now stops at once
  if D: becomes unwritable and syncs before verifying.
* **Batch 1 (2026-11-11):** the oldest artifacts — every directory whose newest file predates
  2026-10-15 (milestones M2–M8 and early M6 adaptive runs, ≈34 GB, 201 directories), list in
  [`results/records/artifact-offload/batch-1-old-items.txt`](../../results/records/artifact-offload/batch-1-old-items.txt),
  except `m2-data24-parquet`, `m3-data24-parquet-iid-local-test-v1`, `m5-secure-multiround-local-test-v1`
  (dataset and starting model, still required).
* **Batch 2 (2026-11-13):** completed November revision studies, 36 items, ≈107 GB of
  source data. The list is in
  [`results/records/artifact-offload/batch-2-items.txt`](../../results/records/artifact-offload/batch-2-items.txt).
  21 studies closed between 2 and 6 November were moved whole. For `capped-final-v1`,
  `gate-trajectories-v1`, `head-gate-v2`, `head-gate-v2-confirm`, `trigger-probe-live`,
  `trigger-probe-evasion-live`, `probe-keynorm-confirm` and `global-probe-confirm` only the
  case folders moved (`cases/`, `evaluation*/cases`, `guard/cases`, plus
  `head-gate-v2/evaluation-exploratory` and `capped-final-v1/interrupted-attempts`).
  In the first pass 6 items failed and were left untouched: five held swtpm state files
  readable only by root, and the 15 GB `capped-final-v1/cases` archive ran out of memory.
  A second pass run as root archived all six.
  Inside WSL, disk use dropped from 172 GB to 63 GB.
* Further batches only on request.

## Kept on C: (needed by running or planned work)

`m2-data24-parquet`, `m3-data24-parquet-iid-local-test-v1` (data, validation, test),
`m5-secure-multiround-local-test-v1` (starting model), `revision-bounded-influence-v1`
(clipping limits), `revision-clean-gate-calibration-v1` (clean histories, training protocol),
`revision-dba-three-seed-v1`, `revision-live-bounded-tpm-v2` (source workspace for the live
rollback), `revision-live-probe-rollback-v1` and `revision-live-probe-rollback-fedavg-v1`
(study still in progress), `revision-head-cusum-gate-v1` (evaluation awaiting approval),
`maintenance/`, `ton-iot-robust-transfer-v1`, and everything under ~300 MB.
For every study in the PRIOR chain (`capped-final-v1`, `gate-trajectories-v1`, `head-gate-v2`,
`head-gate-v2-confirm`, `trigger-probe-live`, `trigger-probe-evasion-live`,
`probe-keynorm-confirm`, `global-probe-confirm`), `partitions/` stays on C: because the
partition-distinctness checks need it, together with protocols, models, decisions and
summaries. Only their case evidence was moved.

## Restoring

```bash
tar -I pigz -xf /mnt/d/fl-artifacts-archive/<archive>.tar.gz -C artifacts
sha256sum /mnt/d/fl-artifacts-archive/<archive>.tar.gz   # compare with the manifest first
```

Scripts that re-verify an offloaded study (and the trigger-probe development scripts, which
read `revision-head-gate-v2/evaluation-exploratory/cases`) need the archive restored first.
If D: is not visible in WSL: `sudo mkdir -p /mnt/d && sudo mount -t drvfs D: /mnt/d`.
