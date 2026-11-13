# Witness operational handover: recovery, restart and local access checks

## Completed result

The existing core is unchanged. The new standalone operator utility
`scripts/witness_operator.py` verifies, backs up and restores **sealed** witness
state using independently retained policy and final-closure digest inputs.
It never initializes a missing database. Backups use SQLite's backup API, retain
the original witness key and signed history, and are checked again after copying.
Source and destination must be distinct; an existing destination is never replaced.
Private directories/files are created with modes 0700/0600 from their first byte.

Tests use copies of the actual external-TSA campaign, including fifteen
TPM-signed client receipts and sixteen original external timestamp tokens.
No new TSA request, receipt signature, deadline or final closure was created.
All historical state remains unchanged. The resulting snapshot after backup
and restore is identical to the original signed snapshot.

| Check | Actual outcome |
| --- | --- |
| Sealed backup and restoration | All 15 registrations and the exact closure retained |
| Force-killed witness process | Exit 137, then service restarted successfully |
| Duplicate submission and repeated close after restart | Original acknowledgement and closure returned unchanged |
| Local coordinator identity without privileges | Four key/database read/write attempts denied with EACCES |
| HTTP close/reset/init and private-file routes | All six requests rejected with 404 |
| Receipt with original valid structure but coordinator signature | Rejected with 409 as an invalid authenticated client receipt |
| Actual HTTPS service using a development CA | Original signed snapshot retrieved and verified |
| Wrong HTTPS hostname or untrusted CA | Both TLS handshakes rejected |
| Non-loopback listener without TLS | Rejected before opening state |
| Ten invalid recovery cases | All rejected |

The recovery negatives cover a missing journal (not silently recreated), wrong
policy pin, wrong closure pin, truncated history, unsealed state, wrong private
key, unsafe private-key permissions, symlink substitution, altered backup file
manifest and an already occupied destination. The sentinel in the occupied
destination is preserved. Recovery also checks all fifteen retained client
acknowledgements and authenticates the original external timestamps offline.

The public report/package contains no private PEM key blocks. Actual backups,
service state and development TLS private keys remain under the original WSL
`artifacts/revision-witness-operations-20261105-v1` private directory. A backup
contains the witness signing key and must stay under the witness operator's
control; it is not a public evidence export.

## Exact assurance boundary

The access probe uses Linux UID/GID 65534, a read-write state mount and no
capabilities. Read/write denial is caused by ownership/permissions, not a
read-only mount. The host/Docker administrator can still bypass that boundary.
Neither this test nor local development TLS establishes administrative
independence. A real separately controlled operator, credentials, journal,
backups and public pin distribution are still unavailable and unvalidated.

The new utility supports sealed state only. No open-round backup, rollback of
unacknowledged in-flight work, power-loss storage behavior or crash during a
SQLite commit was tested. The crash probe kills the process after acknowledged
commits. This tool is an additional operator recovery path: it does not change
the base service's first-start initialization behavior or provide a general
rollback detector for an open journal. An open campaign needs a separate
coherent recovery plan and externally retained client acknowledgements.

The original 127-module core and executed image remain identical at
`140c7302014e7a4639775b356ae44dabc0f88b6c29ea60d5e226a932f5e132d4`.
The earlier 752-test suite applies to that unchanged core. The new utility
passes static checks and the concrete operational/negative cases above.
The host utility/controller is separately retained and is not TPM-measured.
These operation tests are not an attack-success or model-utility campaign.

No thesis text, equation, graph or PDF was edited; 110 guarded manuscript and
figure files remain identical. ToN-IoT stays deferred. The old closed witness
on port 8765 and every historical experiment remain preserved.

## Audit execution notes

`validation-final.json` is the completed outcome. The first controller finished
the operational checks but exited on its own public-source scan: a literal
private-key marker matched the assertion in its retained Python source. No
private key block was found. That failed run and preliminary result are retained;
the final audit uses anchored PEM-block recognition and additionally checks
HTTPS and a signature-only coordinator forgery with otherwise unchanged receipt
fields. A first TLS audit also stopped while reading the CLI error under the
wrong JSON field; the existing service correctly returned `errors`. The final
audit uses that actual schema and completes successfully. No protocol code or
signed evidence was modified to address either harness issue.

See the final validation, individual check reports, retained controllers and
artifact index. The laboratory procedure below explains how to use the utility.

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
`docs/witness-chain/EXTERNAL_TSA_VALIDATION.md` for the authenticated provider references.

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
