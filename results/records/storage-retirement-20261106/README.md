# Historical targeted-attack replica retirement

On 2026-11-06, four completed early targeted adaptive replicas (seeds 342593,
343593, 344593 and 345593) were retired to recover local disk space, as authorized
by the project owner. Their full per-round client updates and execution traces
were deleted. These campaigns were completed, not invalid; they showed no useful
targeted attack success under the frozen protocol and were superseded for the
current investigation by the retained untargeted and revision campaigns.

Original aggregate reports remain in results/m6-adaptive-multiseed-v1. Their
historical copy, round evaluations, signed campaign manifests, public authority
keys, selected checkpoint bundles and execution locks are retained here without
rewriting their contents. The original exploratory seed 341593-v4 is untouched.
Current revision code, tests and configurations did not reference the four
retired artifact directories in the recorded dependency scan. Historical scripts
and configurations still name them and would need fresh runs to recreate output.

Full TPM chain validation and exact historical trajectory reconstruction for
these four retired replicas are no longer available. Retained checkpoint
manifests can reference deleted inputs. File hashes identify removed bytes;
they are not backups and cannot restore the deleted files. No complete archive
of these four replicas is claimed. Current negative capped-defense results and
all current calibration, replay, formal-model and live-TPM evidence are retained.
The current thesis text was not used as a retention constraint and was not edited.
