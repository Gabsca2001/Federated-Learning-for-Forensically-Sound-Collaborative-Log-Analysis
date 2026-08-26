# M4–M8 overhead benchmarking

## Purpose

This post-M8 profile quantifies the cost of independently checking the already preserved
reference chain. It does not retrain a model and does not rewrite M4–M8 evidence. The output
is a new write-once benchmark workspace containing raw samples, a derived summary, and a
manifest that binds configuration, implementation, source markers, and verifier outcomes.

## Measured boundary

The configured profile measures 13 sequential stages:

1. ephemeral software ECDSA P-256 sign-and-verify pairs;
2. read-only verification of the 15 enrollments and 105 signed M4 appraisal receipts (the
   initial 15-client gate plus 90 campaign-refresh receipts);
3. independent verification of the complete 30-round M5 campaign;
4. M7 prediction, explanation, ATT&CK-mapping, and report verification;
5. M8 inventory, Merkle, timestamp, recovery, campaign-accounting, and final verification.

Timing starts immediately before the verifier function and stops immediately after it. Python
startup and module imports are excluded. Both monotonic wall time and process CPU time are
recorded in nanoseconds. Warmup samples are retained but excluded from the statistics. The
summary reports mean, median, nearest-rank p95, range, and sample standard deviation when at
least two measured repetitions exist.

The M8 verifiers are I/O-heavy and several recursively revalidate upstream sources. Each M8
stage therefore uses one measured repetition with no warmup, avoiding artificial cache-heavy
repetition over multi-gigabyte inputs. A one-sample result is a measured latency, not a
distribution estimate.

## Run and verify

Run from the repository root after confirming that the canonical M4–M8 workspaces still
verify:

```bash
fl-forensics overhead-run \
  --config configs/overhead-local-test-v1.yaml \
  --output artifacts/overhead-local-test-v1

fl-forensics overhead-verify \
  --config configs/overhead-local-test-v1.yaml \
  --workspace artifacts/overhead-local-test-v1
```

Use a new output identifier for every independent execution. The runner rejects a non-empty
output workspace rather than mixing measurements from different host states.

The output files are:

- `samples.json`: warmup and measured wall/CPU durations plus the complete sanitized verifier
  result for each invocation;
- `summary.json`: environment description, interpretation constraints, and recomputed per-stage
  statistics;
- `manifest.json`: configuration and implementation hashes, source snapshots, output hashes,
  stage assertions, and the receipt identifier.

`overhead-verify` does not expect the nondeterministic durations to repeat. It validates every
sample identity and expected verifier outcome, re-hashes the current source markers, recomputes
the statistics, and reconstructs the manifest byte for byte.

## Verified reference execution

The local-test profile completed all 13 stages and 45 measured samples. Verification
recomputed all statistics and 13 source snapshots with zero errors. The receipt is
`overhead-benchmark-242c9f91b96d5b8fad17acff`; its source manifest SHA-256 is
`da7c63073810f3f4295f52f4acd3e55d6a4916b8d0facd0b24cd8ceb7cbd75e9`.

Selected wall-time results are:

| Verification scope | Result |
|---|---:|
| 1,000 software ECDSA sign/verify pairs | median `108.964 ms`; mean `114.016 µs` per pair |
| 15 M4 enrollments and 105 appraisal receipts | median `30.936 ms` |
| Complete M5 campaign, 30 rounds/450 contributions | median `13.342 s` |
| M7 prediction | median `20.716 s` |
| M7 explanation / ATT&CK / report | medians `33.773 / 33.298 / 33.556 s` |
| M8 preservation / Merkle / timestamp | single observations `60.228 / 59.241 / 59.583 s` |
| M8 recovery / accounting / final | single observations `38.907 / 13.204 / 26.110 s` |

The measured-sample total is `773.227 s`, representing repeated experiment work rather than
one request. See the [sanitized result snapshot](../results/overhead-local-test-v1/README.md)
for the complete table, CSV, receipt, and logarithmic figure.

## Interpretation limits

- The M4 receipt stage verifies preserved signed results; it does not issue a new challenge or
  execute a live TPM Quote.
- The software ECDSA result is a development baseline and is not `swtpm` or hardware-TPM
  latency.
- M5 measures full campaign verification, not training or one online aggregation round.
- Filesystem cache state, WSL virtualization, host load, and storage throughput affect results.
- A hash-bound receipt provides internal integrity but cannot prove that the host clock was
  honest. Preserve or externally anchor the finalized receipt when it becomes thesis evidence.

Live runtime overhead requires a separate experiment that measures challenge/Quote, mTLS,
TPM-backed update signing, API transfer, admission, aggregation, and failure recovery under a
declared deployment topology. Those values must not be combined with this offline profile.
