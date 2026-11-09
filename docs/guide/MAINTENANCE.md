# Documentation and evidence maintenance

## Document roles

The root README introduces the framework. `docs/README.md` directs navigation;
`docs/STATUS.md` records current support and limitations; `IMPLEMENTATION_PLAN.md`
contains remaining work. Topic guides explain mechanisms and comparisons.
`docs/documentation-map.json` registers maintained pages, versioned references
and study directories. The reference and result catalogues are generated from
that map.

Versioned protocols, formal releases and study reports remain at their original
paths. Statements such as "current", "pending" or "next" inside those files
refer to their recorded execution. They are not live status or instructions for
the maintained repository. Retained source correspondence is reference material.

## Writing standard

Maintained prose uses professional English and an impersonal technical register.
Each claim names its execution scope and evidence. Instructions use concise
commands with prerequisites and output behavior. Personal narration, campaign
diaries, unsupported superlatives and cumulative progress banners are excluded
from maintained entry points.

Quantitative findings identify their population and endpoint. A checksum pass,
successful experiment completion and successful defense hypothesis are distinct.
Zero ASR, exact parameter restoration and evidence of malicious intent are
separate findings. Historical full-suite counts remain attached to their releases.

## Change procedure

1. Update the relevant topic guide and current status; avoid creating another
   competing status report for the same claim.
2. Register new references/studies in `documentation-map.json`, retaining their
   exact profile identifier and evidence entry point.
3. Regenerate catalogues with `make docs-index` and run `make docs-check`.
4. Check changed commands through `make help`, appropriate dry runs and focused
   tests. Fresh expensive scientific runs require a separate protocol.
5. Preserve old publications and their checksums. Corrections belong in a new
   qualified study or maintained explanation, not inside a sealed report.

## Retention and storage

The catalogue is a navigation layer, not a release/sanitization certificate.
Local results include uncommitted research work. Runtime artifacts can contain
trust state and large models; dataset and artifact directories are not generic
cleanup targets. Deleting or moving pinned evidence can break formal closures,
research source locks and replay. Any storage retirement needs a separate
inventory of references and retained conclusions.

The consolidation inventory checks every original project-owned Markdown outside
third-party environments and raw data. Historical references and publication
Markdown are preserved byte-for-byte; mutable entry points are backed up in the
documentation-consolidation work record. Known historical link defects are
reported separately from defects in the maintained guide.

Routine `make docs-check` scans the maintained/reference and result folders and
checks the retained runtime pages by their inventory paths. A complete discovery
of newly generated runtime Markdown is available through
`.venv/bin/python scripts/repository_audit.py docs --scan-runtime`. This avoids
walking unrelated model and TPM payload trees on every routine documentation check.

## Historical local-link interpretation

The 8 November inventory records 74 unresolved local references: 72 in historical
artifact snapshots and two in preserved result documents. Snapshot-relative links
can retain their original source-tree layout. The two result-document references
have the following related navigation routes:

| Preserved document | Related reference |
| --- | --- |
| `revision-final-formal-correspondence-v2/CURRENT_RELEASE_PROOF_ANNEX.md` | [Profile correspondence overview](../FORMAL_PROFILE_CORRESPONDENCE.md) |
| `storage-retirement-20261106/historical-summary/README.md` | [Original multiround protocol](../M6_ADAPTIVE_MULTIROUND.md) |

These routes aid consultation; they do not substitute a current reference for
the exact bytes committed by an earlier closure. Release verification continues
to use its own retained artifacts and source digests.
