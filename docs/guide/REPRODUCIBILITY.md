# Reproducibility and controlled execution

Commands are issued from the original repository root in Linux/WSL2. The default
Make target prints help. Existing experiment directories are not overwritten.

## Environment and inexpensive checks

```bash
make setup
make check
make docs-check
make evidence-list
make evidence-check
```

`setup` creates the selected virtual environment and installs the declared ML,
simulation, reporting and development extras. `check` checks package dependencies
and the CLI; `doctor` additionally checks Docker Compose and OpenSSL. Existing
environments need not be reinstalled for documentation checks.

| Target | Operation | Writes or expensive work |
| --- | --- | --- |
| `docs-check` | Maintained links, complete catalogues, professional style and retained Markdown hashes | Read-only; no network |
| `docs-index` | Regenerate the two catalogues from the documentation map | Only the declared index files |
| `evidence-list` | List retained study directories and their entry points | Read-only |
| `evidence-check` | Check the selected flat checksum publication against its catalogued index | Read-only; no new inference, replay or signatures |
| `test-docs` | Repository-checker regression cases | Temporary test directories |
| `test-formal` | Selected formal/coverage/review/derivation tests | Test workspaces |
| `test-groups` | Selected retrospective, episode and diagnostic tests | Test workspaces |
| `test` | Complete pytest suite | Potentially broader integration work |
| `validate` | Existing package, tests, lint and fixture smoke workflow | Fresh fixture output required |

The default evidence check selects the completed V5 publication. Another study
with a flat `file-checksums.json` index can be selected explicitly:

```bash
make evidence-check STUDY=results/revision-attribution-origin-recovery-v1
make smoke DEMO_WORKSPACE=artifacts/documentation-smoke-new
```

Stored-checksum verification is distinct from fresh numerical reproduction and
independent trust authentication. Profile-specific signed manifests and full
verifiers remain authoritative for their separate claims.

## Data and M2–M3 reconstruction

```bash
make dataset-download DATA24_SOURCE=data/raw/uwf-zeekdata24/parquet-new
make dataset-verify DATA24_SOURCE=data/raw/uwf-zeekdata24/parquet
make foundation
```

`dataset-download` downloads the pinned source into a new destination;
`dataset-verify` checks existing pinned files without downloading or writing.
`foundation` executes M2 then M3 and requires all selected output paths to be
fresh. Path variables are listed by `make help` and the Makefile. The controlled
source manifest must already exist. No ToN-IoT download is part of these targets.

## Official ToN-IoT preflight

The [ToN-IoT validation entry](../TON_IOT_VALIDATION.md) describes the acquired
official collection, 25-feature mapping and remaining evaluation boundary.
`make test-ton-iot` runs the focused mapping and field-audit checks. A full scan
reads the external source index without extraction or model training:

```bash
make ton-iot-preflight \
  TON_IOT_INDEX=/path/to/ToN-IoT-official/collection-complete.json \
  TON_IOT_OUTPUT=artifacts/ton-iot-preflight-new
```

The index must exist and the selected output path must be fresh. The resulting
report identifies source occurrences and cannot alone establish distinct
connections or model generalization.

## Profile-specific runtime and research

M4–M8 deployments require explicit configuration, namespace, trust state and
input evidence. The [reference catalogue](../REFERENCE_INDEX.md) links the
original milestone procedures. The [framework guide](FRAMEWORK.md) identifies
the selected witnessed integration profile.

Research controllers can intentionally stop or reject repeated output paths.
Some completion, report and recovery controllers are retained inside their
publication rather than installed as a general reusable CLI. In particular,
the V5 publication retains the exact resumed generator, fresh verifier and
accounting scripts. Running its already-completed phase commands again is not
a supported substitute for a fresh prespecified experiment.

No convenience target launches a new attack campaign, deletes artifacts,
changes Docker state, requests a timestamp or edits the manuscript. A full
reproduction requires its named protocol, preserved inputs, compatible runtime,
fresh output paths and an explicit storage budget.
