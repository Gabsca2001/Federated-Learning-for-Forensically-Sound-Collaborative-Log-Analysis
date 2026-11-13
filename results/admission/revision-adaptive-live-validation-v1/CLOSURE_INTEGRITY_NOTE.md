# Active completion closure

Use `completion-closure-v2.json` and `analyst-v2.public.pem` as the active
completion. The first closure correctly signed its own core but prematurely
hashed `finalization.log` while that redirected stdout file was still open.
Its last progress line changed that one log after signing. The original closure,
its public key and all experiment evidence are preserved unchanged.

Version 2 hashes the completed outputs after all writers have exited. No source,
model, metric, training, TPM evidence, maintained document or validation result
is changed by this closure repair. The analyst signature remains a local
integrity record, not an independent witness or trusted timestamp.
