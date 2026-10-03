# M6 adaptive untargeted campaign: seed 342593 continuation

This addendum records the runtime incident and the guarded continuation of the
pre-specified four-arm experiment in M6_ADAPTIVE_UNTARGETED_LIVE_V1.md. The
scientific plan, seed, policies, attack schedule, validation-only search, query
budget, data split and locked sources are unchanged.

## Incident

On 2026-10-01, the first infrastructure-recovery launch completed M4 setup and
verified 93 of the 120 planned arm-rounds. gated_clean round 24 also verified.
While the frozen runner was signing the adaptive candidate for
gated_adaptive round 24, Docker failed to start the one-off client05 container
when mounting its 64 MiB /tmp, reporting "no space left on device". The
container process did not start. This was not host or Docker data-disk
exhaustion: both had hundreds of gigabytes free.

Docker Desktop's Linux kernel had fs.mount-max=100000 with 99,938 mounts in
/proc/1/mountinfo. The available mount table entries were exhausted by the
accumulated Compose mounts. The runtime limit was temporarily raised to 200,000;
no Docker Desktop, WSL, or TPM container was restarted. A smoke test with the
locked M5 image then mounted the same tmpfs successfully. This kernel setting
is runtime-only and may reset when Docker Desktop restarts.

## Preserved state and safe continuation

The original recovery log and process receipt are preserved. The process
receipt's "running" value is stale after the Python process exited; it is not
used as proof of a live process. All 15 persistent TPM containers remain
healthy with their original start times.

At the interruption, the signed selection had already bound query 32. The
validation-only search receipt records 66 queries, confirms its source hashes,
and says test_data_accessed=false. Client02's signed adaptive submission and
the untreated client01, client03 and client04 proposals are preserved.
Client05's failed staging directory is empty; client14 signing had not started.
No aggregation checkpoint or M6 round-verification output existed for
gated_adaptive round 24. The other two arms had not yet reached round 24.

The separate continuation script is
scripts/resume_m6_adaptive_untargeted_paired_s342593_v1.py. Its preflight
checks the frozen source lock, execution lock, the 93 prior VERIFIED markers,
the exact partial-round file set, coordinator authorization, selected query,
submission provenance, network identity and all TPM start times. It recomputes
the recorded 66-query validation search in verifier mode. The preflight passed:
selected query 32 was reproduced, all bindings matched and no test data was
accessed.

The continuation preserves every existing signature, proposal, log, lock and
receipt. It completes only missing round-24 submissions and aggregation, then
runs tpm_clean and tpm_adaptive round 24, followed by rounds 25–30 for all
four arms and the original M5 finalization and verification gates. It does not
rerun the fresh-only launcher. If an unexpected partial artifact, lock change,
TPM restart, or verification error appears, it stops for diagnosis.

## Recovery records

- Frozen experiment: configs/m6-adaptive-untargeted-paired-s342593-v1.json
- Scientific lock: configs/m6-adaptive-untargeted-paired-s342593-v1.lock.json
- Infrastructure setup: docs/M6_ADAPTIVE_UNTARGETED_INFRA_RECOVERY_V1.md
- Continuation: scripts/resume_m6_adaptive_untargeted_paired_s342593_v1.py
- Preserved original log: m6-adaptive-untargeted-paired-v1-recovery.log
- First lock-check failure log: m6-adaptive-untargeted-paired-v1-resume.log
- M5 workspace failure log: m6-adaptive-untargeted-paired-v1-resume2.log
- Expired-context failure log: m6-adaptive-untargeted-paired-v1-resume3.log
- Stale process receipts: artifacts/m6-adaptive-untargeted-paired-s342593-v1-resume-process.json and artifacts/m6-adaptive-untargeted-paired-s342593-v1-resume-process-v2.json
- Round-24 recovery receipt: artifacts/m6-adaptive-untargeted-paired-s342593-v1-round24-resume-receipt.json
- Final continuation receipt: artifacts/m6-adaptive-untargeted-paired-s342593-v1-resume-completion.json

At the time this note was written, the preflight had passed and the
continuation process had not yet been launched. No new campaign result is
claimed until all 120 arm-rounds and final verification complete.


## Source-lock guard during preparation

A first invocation of the continuation stopped at the frozen-source check
because the preceding documentation edit had appended a note to the locked
campaign specification. No process receipt was written and no signing,
training, or campaign artifact was created. The specification was restored
byte-for-byte to its locked SHA-256 and the full lock check was rerun. The
failed invocation log is retained as
m6-adaptive-untargeted-paired-v1-resume.log; the next attempt uses a distinct
log, m6-adaptive-untargeted-paired-v1-resume2.log.

## Launch update

After restoring the locked campaign specification byte-for-byte, all frozen
input hashes matched. The guarded continuation was launched once on
2026-10-01 (PID 3254152), using the distinct log
m6-adaptive-untargeted-paired-v1-resume2.log. Process inspection confirmed it
was active in the missing client05 signing step for gated_adaptive round 24.
This is an execution-status update only; no additional round is claimed verified
until its official M5/M6 verifier succeeds.

## M5 workspace environment correction

The second continuation attempt started the client05 container successfully but
stopped before TPM signing because its Compose environment lacked M5_WORKSPACE;
the signer could not read /campaign/public. The failed container produced no
submission, its separate staging directory is empty, and the 15 TPM containers
remain healthy. Its log and process receipt are preserved. The continuation now
sets the same M5_WORKSPACE and M5_COORDINATOR_WORKSPACE values used by the
frozen runner. The next attempt uses a new log, receipt and staging root; it
will preserve the previous attempt's empty staging and records.

## Stop condition: round-context expiry

The third continuation attempt reached the M5 signer, which rejected the
existing signed round context as expired. Its signed expires_at is
2026-10-01T03:50:38Z. The signer requires the current time to remain within the
signed issued_at/expires_at interval; the selection and candidate are bound to
that context. Refreshing or editing the context, changing the clock, or bypassing
M5 validation would invalidate the forensic and cryptographic evidence, so no
further signing or aggregation attempt was made.

The failed signer wrote no client05 submission. The client05 staging directory
for this attempt is empty; client14 was not attempted. No round-24 checkpoint,
round verification receipt, or campaign completion receipt exists. The original
workspace still has 93 verified arm-rounds and the same locked partial round.
All 15 TPM containers remain healthy with their original start times. Logs and
both stale process receipts are preserved.

The continuation wrapper must not be launched again. A valid next experiment
would need a separate, explicitly planned workspace/branch and a new M5 round
context; it must preserve this campaign and all its evidence. Deciding whether
to reuse verified rounds in a separate copy or repeat the campaign is a
separate experimental choice. No result from this incomplete four-arm run is
claimed.


The third attempt ran as PID 3255590 and is recorded by the second process
receipt. It reached client05 signing with the M5 workspace mounted, but M5
rejected the expired round context. Both process receipts now describe exited
processes and must not be treated as live status. The three attempt logs remain
separate and unmodified.
