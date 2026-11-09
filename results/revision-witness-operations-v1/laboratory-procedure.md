# Laboratory operator procedure — sealed witness recovery

The missing input is a real trusted operator with administration outside the
coordinator's control. This kit does not assign a fictitious person or host.
Before initial registration that operator must generate and retain the witness
key and journal, supply a client-trusted TLS identity for the actual remote
host, and distribute the witness public key and policy digest independently.
After closure they must also independently distribute the final closure digest.
The locally tested TLS CA is only a development certificate and is not supplied
as a production trust anchor.

## Run a fresh campaign

Use normal M4 enrollment/fresh appraisal and M5 round initialization, export
the verified enrolled keys, then call the existing `witness-init` with a new
state directory and a cutoff inside context validity. Leave time for training,
timestamp request spacing, closure and actual M5 admission before expiry.
The verified external TSA profile is Sectigo HTTPS `/qualified`, OID
`0.4.0.2023.1.1`, maximum signed accuracy 1,000,000 microseconds. Its root DER
SHA256 is `f871f8976b4068d700d5f281084b4a29eaf4b8f35743330ba062fab46f58c2ed`.
Retain the actual policy-pinned PEM trust store. It has its own file SHA256,
which must not be confused with the DER certificate fingerprint. See
`docs/EXTERNAL_TSA_VALIDATION.md` for the authenticated provider references.

On a remote host, `witness-serve` needs both `--tls-cert` and
`--tls-private-key`; non-loopback plaintext is rejected. The operator's local
CLI, not the public HTTP API, performs closure. Then run actual witnessed M5
admission and verify the public package against independently received pins.
Initial registration, fresh-context setup and live admission remain the existing
protocol; this recovery utility does not replace them.

## Check, back up and restore a closed campaign

Run from the original repository and its Python environment. Substitute actual
operator paths and independently retained digests; never derive your trusted
pins solely from the backup you are trying to authenticate. Include every
retained client acknowledgement by repeating `--acknowledgement`.

```bash
.venv/bin/python scripts/witness_operator.py check \
  --state /srv/witness/closed-round \
  --expected-policy-digest POLICY_DIGEST \
  --expected-closure-digest CLOSURE_DIGEST \
  --acknowledgement /srv/witness/client-copies/client01-ack.json

.venv/bin/python scripts/witness_operator.py backup \
  --state /srv/witness/closed-round \
  --output /srv/witness-backups/round-unique-backup \
  --expected-policy-digest POLICY_DIGEST \
  --expected-closure-digest CLOSURE_DIGEST \
  --acknowledgement /srv/witness/client-copies/client01-ack.json

.venv/bin/python scripts/witness_operator.py restore \
  --state /srv/witness-backups/round-unique-backup \
  --output /srv/witness/round-recovered \
  --expected-policy-digest POLICY_DIGEST \
  --expected-closure-digest CLOSURE_DIGEST \
  --acknowledgement /srv/witness/client-copies/client01-ack.json
```

Destinations must be fresh and outside their source. Keep backup parents under
the separate operator's control, with private state owned by that operator.
The backup manifest detects changed/missing/extra files; it is not a substitute
for independent signature/policy/closure authentication. A partial destination
after an I/O failure remains private and is not automatically overwritten or
accepted; inspect it and choose a fresh destination for the next attempt.

Before any service restart, establish that the intended existing journal and
key are present. In particular, do not treat an absent mounted database as a
fresh campaign or invoke initial setup to recover an old round. Use this sealed
recovery procedure. It refuses open/missing/altered state and does not reopen an
expired context. Normal first-start behavior of the original CLI remains
unchanged. Closed state can serve its snapshot and reproduce old acknowledgements;
it cannot gain new valid registrations.

## Complete real administrative acceptance

Record the actual operators, accounts/hosts, privilege boundaries, TLS identity,
pin distribution channel and backup custody. Verify with the real coordinator
account that it cannot read/change witness private state or administer the host.
Run the full receipt/closure/M5/offline sequence there, preserve a coordinator-
signed omission negative and demonstrate retrieval through an independent
verifier. Repeat restart and restoration checks on that actual storage/service.
The current local UID/TLS tests are rehearsals, not those acceptance results.
