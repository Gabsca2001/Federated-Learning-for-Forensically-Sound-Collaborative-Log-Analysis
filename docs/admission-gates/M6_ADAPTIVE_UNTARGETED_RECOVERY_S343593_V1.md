# M6 untargeted seed 343593 infrastructure recovery

## Incident

The fresh-only seed-343593 runner stopped during initial M4 client01 provisioning.
Docker could not create the Compose trust network because all predefined address
pools were subnetted. Enrollment and training had not begun. The initial stdout
was not redirected to a local log; the preserved
artifacts/m6-adaptive-untargeted-paired-s343593-v1-network-failure-record.json
records this transparently.

## Recovery

The existing M6 infrastructure-recovery procedure was applied without changing
the scientific plan or per-seed lock. The recovery preflight verified the
seed-specific lock and partition, fifteen healthy TPM containers, no prior
enrollments or node files, no existing campaign workspace, and no overlap for
the isolated internal subnet 10.254.253.0/24 with Docker networks or WSL routes.
It then created only the new namespace trust network and provisioned clients
sequentially with Compose --no-deps, reusing the existing TPMs without restart.

M4 enrollment and mTLS both verified all fifteen clients. The unchanged seed
343593 runner then began the four-arm 30-round campaign; every completed round
passes the independent M6 verifier before the next round. Stop on any later
integrity, attestation, partial-round, or TPM-start-time error and preserve the
workspace for diagnosis.

## Recovery records

- Frozen plan and lock: configs/m6-adaptive-untargeted-paired-s343593-v1.json
  and its .lock.json
- Recovery plan and launcher: configs/m6-adaptive-untargeted-paired-s343593-v1-recovery-v1.json
  and scripts/recover_m6_adaptive_untargeted_paired_s343593_v1.py
- Failure record: artifacts/m6-adaptive-untargeted-paired-s343593-v1-network-failure-record.json
- Setup receipt: artifacts/m6-adaptive-untargeted-paired-s343593-v1-network-recovery-receipt.json
- Process receipt: artifacts/m6-adaptive-untargeted-paired-s343593-v1-network-recovery-process.json
