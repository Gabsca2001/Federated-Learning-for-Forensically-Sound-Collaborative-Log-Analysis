#!/bin/bash
# Offload completed-study artifacts to the external SSD (D:), verified, with a manifest.
# Each item: tar+pigz archive under $DEST, verify (full listing + non-directory entry count
# equals source), sha256, then delete the source (or only the declared subpaths).
# Any failure skips the item and deletes nothing. Restore: tar -I pigz -xf ARCHIVE -C artifacts
set -u
cd "$(dirname "$0")/.."
DEST=/mnt/d/fl-artifacts-archive
MANIFEST_D=$DEST/manifest.jsonl
MANIFEST_REPO=results/records/artifact-offload/manifest.jsonl
mkdir -p "$DEST" results/records/artifact-offload
mountpoint -q /mnt/d || { echo "D: not mounted"; exit 1; }

# kind:name[:keep_subdir]   whole = archive and remove all; keep = archive all, remove all but keep_subdir;
# sub = archive and remove only the given subpath (name/subpath)
ITEMS=(
  "sub:revision-head-gate-v2/evaluation-exploratory/cases" "sub:revision-head-gate-v2/guard/cases" "sub:revision-head-gate-v2/evaluation/cases"
  "sub:revision-head-gate-v2-confirm/evaluation/cases" "sub:revision-head-gate-v2-confirm/guard/cases"
  "keep:revision-capped-final-v1:partitions" "keep:revision-gate-trajectories-v1:partitions"
  "whole:revision-research-closure-v1" "whole:revision-severe-tail-gate-v1" "whole:revision-unified-chain-20261105-v2"
  "whole:ton-iot-robust-transfer-v1" "whole:m6-adaptive-untargeted-paired-s343593-v1" "whole:m6-adaptive-untargeted-paired-s342593-v1-continuation-v3"
  "whole:m6-adaptive-untargeted-paired-s344593-v1" "whole:m6-adaptive-untargeted-paired-s345593-v1" "whole:m6-adaptive-untargeted-paired-s342593-v1"
  "whole:revision-formal-alignment-v2" "whole:revision-geometry-detector-v1" "whole:revision-independent-containment-v1"
  "whole:m8-recovery-m6-disagreement-local-test-v1" "whole:m8-recovery-export-local-test-v1" "whole:revision-state-conditioned-heldout-v1"
  "whole:revision-sequential-round-policy-v1" "whole:revision-live-bounded-tpm-v2" "whole:revision-live-envelope-tpm-v2"
  "whole:revision-retrospective-group-validation-v1" "whole:m6-adaptive-paired-s341593-v4" "whole:revision-current-evidence-policy-v1"
  "whole:revision-effective-influence-v1" "whole:revision-attested-dba-v1" "whole:revision-preprocessing-federated-v1"
  "whole:revision-attested-chain-v4" "whole:revision-rolling-envelope-v1" "whole:revision-fedgradtrace-live-v1"
  "whole:revision-state-conditioned-development-v1" "whole:revision-conditioned-groups-v2-fixed-serialization"
  "whole:revision-live-bounded-tamper-v1" "whole:revision-clean-reconstruction-v1"
)

if [ $# -ge 1 ]; then mapfile -t ITEMS < "$1"; echo "items from $1: ${#ITEMS[@]}"; fi

record() { echo "$1" >> "$MANIFEST_D"; echo "$1" >> "$MANIFEST_REPO"; }

for item in "${ITEMS[@]}"; do
  IFS=: read -r kind name keep <<< "$item"
  if ! touch "$DEST/.alive" 2>/dev/null; then echo "ABORT: D: not writable (disconnected?); stopping, nothing else touched"; exit 2; fi
  rm -f "$DEST/.alive"
  src="artifacts/$name"
  if [ ! -e "$src" ]; then echo "SKIP missing $name"; continue; fi
  archive="$DEST/$(echo "$name" | tr '/' '__').tar.gz"
  if [ -e "$archive" ]; then echo "SKIP archive exists $archive"; continue; fi
  bytes=$(du -sb "$src" | cut -f1); files=$(find "$src" ! -type d | wc -l)
  echo "ARCHIVING $name ($((bytes/1000000)) MB, $files entries)"
  if ! tar -I pigz -cf "$archive" -C artifacts "$name" 2> "$archive.err"; then
    echo "FAIL tar $name (see $archive.err); source kept"; rm -f "$archive"; continue; fi
  sync
  listed=$(tar -I pigz -tvf "$archive" | grep -vc '^d')
  if [ "$listed" != "$files" ]; then echo "FAIL verify $name: listed $listed vs $files; source kept"; continue; fi
  sha=$(sha256sum "$archive" | cut -d' ' -f1); size=$(stat -c %s "$archive")
  if [ "$kind" = "keep" ]; then
    find "$src" -mindepth 1 -maxdepth 1 ! -name "$keep" -exec rm -rf {} +; kept="$keep"
  else
    rm -rf "$src"; kept=""
  fi
  rm -f "$archive.err"
  record "{\"date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"artifact\": \"$name\", \"kind\": \"$kind\", \"kept_on_c\": \"$kept\", \"source_bytes\": $bytes, \"source_entries\": $files, \"archive\": \"D:/fl-artifacts-archive/$(basename "$archive")\", \"archive_bytes\": $size, \"archive_sha256\": \"$sha\", \"verified_entries\": $listed, \"restore\": \"tar -I pigz -xf /mnt/d/fl-artifacts-archive/$(basename "$archive") -C artifacts\"}"
  echo "DONE $name -> $(basename "$archive") ($((size/1000000)) MB)"
done
echo "ALL_DONE"
