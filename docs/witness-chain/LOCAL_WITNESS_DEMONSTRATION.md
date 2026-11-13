## Live TPM integration update - 5 November 2026

The old persistent server at port 8765 now exposes its closed two-receipt
development record. It is a receipt witness; the federated coordinator retains
admission and aggregation. That historical store is not reopened or upgraded.

A separate, verified two-case Docker/swtpm campaign now exercises the v2 signed
registration cutoff and the real M5 handoff. See [the live contract and lab
sequence](WITNESS_LIVE_ROUND.md) and [its evidence](../../results/chain-witness/revision-witness-round-v2/README.md).
The new services are stopped for offline verification. Genuine administrative
independence and an externally accepted TSA still require laboratory deployment.
The earlier development-only setup and public-TSA observations below retain
their historical scope.

# Local demonstration and independent laboratory deployment

The local demonstration is a persistent server, not just a one-shot test.
It uses the original WSL repository and the real witness API. Two separately
signed synthetic client receipts are registered at startup. Its timestamp
authority is local development infrastructure. This demonstrates the protocol
under a trusted-host assumption; it does not demonstrate independent control.

## Local server on this PC

While running, open <http://127.0.0.1:8765/policy> to inspect the signed policy.
This endpoint returns JSON, not a graphical dashboard. The completed snapshot
becomes available at `/snapshot` only after the operator closes the context.
The default context window is one hour from its first initialization. Restart
does not extend the deadline or regenerate keys/acknowledgements.

The private state is retained in WSL at:

`/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis/artifacts/revision-local-witness-server-20261104`

In the original WSL repository, run:

```sh
.venv/bin/python scripts/revision_local_witness_server.py --workspace artifacts/revision-local-witness-server-20261104
```

This foreground invocation keeps the service available until interrupted.
If it is already running, use that existing instance. To stop the task-owned
controller and witness while preserving state:

```sh
.venv/bin/python scripts/revision_local_witness_server.py --workspace artifacts/revision-local-witness-server-20261104 --stop
```

The stop action checks the recorded PID start time and command fingerprint;
it does not stop other Python processes or Docker engines. To close the
registration set after its deadline:

```sh
.venv/bin/python -m fl_forensics.cli witness-close --state artifacts/revision-local-witness-server-20261104/witness-state --output artifacts/revision-local-witness-server-20261104/closed-snapshot.json
```

For a fresh, shorter demonstration, select a new workspace and unused ports;
for example use a 60-second window, witness port 8767 and TSA port 8768.
Do not delete or rewrite the old context to simulate a new deadline. This
launcher uses test-data fixtures intentionally; it is not the laboratory's
production TSA implementation or a real-data client provisioner.

## What the laboratory must supply

The external step needs an administrator and account whose witness key and
journal are inaccessible to the coordinator. A laboratory-managed Linux host
is sufficient for a research deployment if those permissions and the trusted
administrator assumption are explicit. A second process/container on the
same fully shared administrator account does not establish the separation.

The operator supplies a TLS hostname/certificate, externally pinned enrollment
authority and coordinator keys, and an accepted RFC 3161 TSA trust store,
policy OID and accuracy bound. The endpoint must provide explicit signed
accuracy compatible with the existing verifier. Choosing a familiar public
name is not evidence that every response meets this profile.

Use the existing CLI in this order:

1. Export client ESK keys/levels with `witness-enrollment-keys`, providing the
   authority and coordinator public keys through the laboratory's trusted channel.
2. Initialize a new witness state with `witness-init`. Keep its private key and
   database on the witness host. Distribute its public key and policy digest
   separately from coordinator-supplied evidence.
3. Start `witness-serve` on the laboratory host with TLS enabled. Clients use
   `witness-submit` and retain their verified signed acknowledgements.
4. After the deadline, the laboratory operator runs `witness-close` and retains
   the final closure digest in an account/store outside coordinator control.
   Give the verifier this reference through that trusted channel.
5. The verifier retrieves the snapshot using `witness-fetch`, then checks it
   with `witness-verify`, the independent pins and retained acknowledgements.
   Add inventory/payload inputs to reconstruct eligible intake outcomes.
6. Repeat omission, extra-entry, truncation, replay, late-registration and
   unavailable-TSA controls. An unavailable/unsupported authority must fail
   closed, rather than silently using the local clock.

The necessary handover facts are hostname, witness administrator/key custodian,
coordinator administrator, approved TSA/CA/policy/accuracy, and who retains and
distributes policy/final-closure digests. No account, paid service or deployment
outside this PC has been created. No secret is included in this handover folder.

## Actual public-TSA compatibility observation

A synthetic request to FreeTSA returned a response without explicit signed
accuracy; the existing verifier rejected it. The official FreeTSA page was used
to pin its published CA fingerprint. A DigiCert HTTPS probe was refused at
connection establishment in this environment; the official page advertises an
HTTP timestamp endpoint. Neither result establishes suitability or unsuitability
of every service/profile offered by those organizations. No production TSA has
been selected or institutionally accepted, and no verification requirement was
relaxed. Only synthetic imprints were used; thesis data was not transmitted.

Sources checked on 4 November 2026:
[FreeTSA](https://freetsa.org/index_en.php) and
[DigiCert timestamp documentation](https://knowledge.digicert.com/general-information/rfc3161-compliant-time-stamp-authority-server).

Full protocol assumptions and command arguments remain in the repository's
`docs/witness-chain/INDEPENDENT_SUBMISSION_WITNESS.md`. Delivery to the coordinator, final
admission and witness honesty remain separate conditions.
