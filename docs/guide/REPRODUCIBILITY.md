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
make evidence-check STUDY=results/admission/revision-attribution-origin-recovery-v1
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
input evidence; the Make targets below use the reference `local-test-v1` profile. The [reference catalogue](../REFERENCE_INDEX.md) links the
original milestone procedures. The [framework guide](FRAMEWORK.md) identifies
the selected witnessed integration profile.

Research controllers can intentionally stop or reject repeated output paths.
Some completion, report and recovery controllers are retained inside their
publication rather than installed as a general reusable CLI. In particular,
the V5 publication retains the exact resumed generator, fresh verifier and
accounting scripts. Running its already-completed phase commands again is not
a supported substitute for a fresh prespecified experiment.

## Re-running completed experiments

`make experiments` lists one target per study that can be re-run with its own
controller. Nothing starts unless the target is named.

```bash
make experiments
make probe-keynorm PHASE=calibrate
make probe-keynorm PHASE=prepare
make probe-keynorm PHASE=guard WORKERS=2
make probe-keynorm PHASE=verify-guard
make probe-keynorm PHASE=guard-decide
make probe-keynorm PHASE=evaluation WORKERS=2
make probe-keynorm PHASE=verify-evaluation
make probe-keynorm PHASE=test
make probe-keynorm PHASE=report
```

| Group | Targets | How they run |
| --- | --- | --- |
| Gate and probe studies | `gate-factorial`, `head-cusum`, `head-v2`, `head-v2-confirm`, `trigger-probe`, `probe-evasion`, `probe-keynorm`, `global-probe` | One phase at a time with `PHASE=`; a study only offers the phases it has |
| Signed live case | `live-probe-rollback LAB=artifacts/<fresh>` | Needs Docker and the probe-rollback image |
| Single-pipeline studies | `clean-gate-calibration`, `severe-tail-gate`, `gate-trajectories`, `gate-mechanism-audit`, `mass-safety` | Run, verify and report in sequence |
| External datasets | `multisource-fl`, `multisource-confirmation`, `two-view-confirmation`, `unsw-generalization`, `unsw-s0-confirmation`, `label-efficiency`, `lofo`, `domain-adaptation`, `domain-adaptation-controls`, `prototype-reanchoring`, `ton-iot-robust-transfer PHASE=train\|evaluate` | Each controller refuses to run if its frozen protocol digest has changed |
| Milestone replays | `m6-policy-sensitivity-replay`, `m6-adaptive-frozen-verify` | Re-verify stored M6 results |

Before a re-run:

- Controllers never overwrite a finished study. Where the target accepts `LAB=`,
  it should point to a fresh folder. `probe-evasion`, `probe-keynorm` and
  `global-probe` use a fixed folder, which has to be moved aside first.
- Some inputs are on the external SSD. `make restore-artifact ARCHIVE=<name>`
  checks the archive's SHA-256 against the offload manifest before extracting it
  into `artifacts/`, and never replaces existing files. The
  [offload record](../records/ARTIFACT_OFFLOAD.md) explains what is stored where.
  For example, `gate-mechanism-audit` needs the M6 pilot campaigns restored first.
- Training phases take hours. Keep `WORKERS` at 2 or below under the WSL memory limit.
- A re-run is a fresh repetition under the same protocol, not a byte-for-byte
  replay: the original evidence stays in its publication folder.

## M4–M8 reference chain

The milestone procedures in `docs/milestones/` are also available as targets,
using the `local-test-v1` paths of the reference chain:

```bash
make m4
make m5-build
make m5
make m6-disagreement
make m6-frozen-comparison
make m7
make m8
```

`m4` deploys, enrols and attests the 15 software-TPM clients; `m5` must follow
it without restarting the TPM services, then verifies the campaign and writes its
report. `m7` investigates round 11 on the first six test cases. `m8` preserves,
anchors, exports and accounts for the campaign; its timestamp step contacts the
TSA declared in `configs/timestamp-local-test-v1.yaml`, so it needs network
access. `m4-stop` stops the TPM services without deleting their state, and
`m5-verify` and `m8-verify` re-check existing outputs. Every target refuses
existing outputs and names any missing input.

The studies in `results/admission/` have no Make target. Their controllers are
kept inside each publication folder and follow the procedure described in its
README.

No target deletes artifacts or TPM volumes or edits the manuscript.
