# Unreferenced artifact retirement (2026-11-10)

On 2026-11-10 the Windows volume holding the WSL disk image ran out of space,
which stopped the head-CUSUM evaluation and made WSL unable to start. To recover
space, the project owner authorized deleting 19 artifact directories (5.40 GB,
47,224 files) that no tracked file in src/, scripts/, configs/, tests/, docs/ or
results/ referenced by path. The owner accepted that these campaigns would be
re-run if they are needed again.

Retired directories (full list with byte and file counts in
`retired-directories.tsv`):

- m3-multiseed-v2-retry1
- m3-data24-parquet-non-iid-fedavg
- revision-live-bounded-tpm-v1 (superseded by revision-live-bounded-tpm-v2)
- revision-formal-alignment-v1 (superseded by revision-formal-alignment-v2)
- revision-dba-pilot-v1 … v5 (pilots)
- m6-downplus10-{clean,disagreement}-s{341593..345593}-v1 (10 runs)

The small sibling directories `m6-downplus10-*-v1-trust` and `-v1-nodes` were
not deleted.

`file-inventory.sha256.gz` lists the SHA-256 of every deleted file that was
readable when it was deleted. The software-TPM state files under
`revision-live-bounded-tpm-v1/tpm-state/client*/` (`.lock`, `tpm2-00.permall`)
were owned by another user and could not be hashed, so they are missing from the
inventory. File hashes identify the removed bytes: they are not a backup and
cannot restore the files. No archive of these directories is claimed.

The thesis text was not searched before deletion: WSL could not run when the
check was attempted.
