# M6 adaptive untargeted campaign: infrastructure recovery v1

This supplement records an infrastructure-only recovery for the frozen
four-arm campaign in `M6_ADAPTIVE_UNTARGETED_LIVE_V1.md`. It does not change
the attack, seed, arms, schedule, query budget, evaluation split, or policies.

## Incident and recovery boundary

The first launch stopped while Compose tried to create the isolated M4
`trust` network and Docker reported `all predefined address pools have been fully subnetted`.
It stopped before client01 provisioning, enrollment, or training. The 15 fresh
TPM containers remained healthy; the trust registry had no enrollments, client
node workspaces had no files, and the campaign workspace did not exist. The
failed log is retained and ignored by Git.

Recovery assigns only this namespace's internal Compose `trust` network the
explicit subnet `10.254.254.0/24`, after checking current Docker networks and
WSL routes for overlap. The launcher uses the same pre-specified plan, static
source lock, existing M4 trust authority, and locked images. It provisions the
official client services sequentially with `--no-deps`, reusing the live TPMs
without asking Compose to start or restart them. It then runs the existing M4
enrollment and mTLS checks. The unchanged frozen runner executes and verifies
all four trajectories.

The launcher refuses duplicate or partial recovery, changed lock inputs,
changed TPM start times, non-empty enrollments, unexpected containers, or
existing campaign artifacts. It preserves every prior artifact and log. A
separate setup receipt records recovery details; the original scientific lock
remains authoritative.

## Recovery records

- Parameters: `configs/m6-adaptive-untargeted-paired-s342593-v1-recovery-v1.json`
- Launcher: `scripts/recover_m6_adaptive_untargeted_paired_v1.py`
- Setup receipt: `artifacts/m6-adaptive-untargeted-paired-s342593-v1-recovery-receipt.json`
- Process receipt: `artifacts/m6-adaptive-untargeted-paired-s342593-v1-recovery-process.json`
- Recovery log: `m6-adaptive-untargeted-paired-v1-recovery.log`


## Follow-up

The trust-network recovery succeeded, but it did not complete the experiment.
Docker later exhausted its runtime mount table during a client-signing
container. See M6_ADAPTIVE_UNTARGETED_RESUME_S342593_V1.md for the measured
cause, preserved partial state, successful validation-only preflight and
continuation procedure.


## Seed replications 343593–345593

The same Docker automatic-address-pool exhaustion recurred during fresh M4 trust
network creation, before enrollment or training, for the later seed replications.
Recovery used one isolated internal subnet per namespace after checking Docker
network CIDRs and WSL routes for overlap:

| Seed | Internal trust subnet | Recovery record |
|---:|---:|---|
| 343593 | `10.254.253.0/24` | [recovery record](M6_ADAPTIVE_UNTARGETED_RECOVERY_S343593_V1.md) |
| 344593 | `10.254.252.0/24` | `../artifacts/m6-adaptive-untargeted-paired-s344593-v1-network-recovery-receipt.json` |
| 345593 | `10.254.251.0/24` | `../artifacts/m6-adaptive-untargeted-paired-s345593-v1-network-recovery-receipt.json` |

For s345593, the original fresh-run output is preserved in the local ignored log
`../m6-adaptive-untargeted-paired-s345593-v1.log`; its SHA-256 is recorded in the
failure record. The recovery plan and corrected v2 launcher are
`configs/m6-adaptive-untargeted-paired-s345593-v1-recovery-v2.json` and
`scripts/recover_m6_adaptive_untargeted_paired_s345593_v2.py`. The recovery
preflight confirmed all 15 TPMs healthy, no enrollment requests or registry
entries, no campaign workspace, an unchanged scientific lock, and no subnet
overlap. M4 enrollment and mTLS then passed; the frozen runner verified all
four arms and stopped its TPMs normally. Its local ignored recovery log is
`../m6-adaptive-untargeted-paired-s345593-v1-recovery-v2.log`.

The recovery scripts did not change the attack, seed, round schedule, query
budget, policy, model, or scientific lock. All campaign workspaces, original
logs, incident records, recovery receipts, and failed-attempt evidence remain
preserved. The combined four-seed results are in
[`M6_ADAPTIVE_UNTARGETED_MULTISEED_RESULTS_V1.md`](M6_ADAPTIVE_UNTARGETED_MULTISEED_RESULTS_V1.md).
