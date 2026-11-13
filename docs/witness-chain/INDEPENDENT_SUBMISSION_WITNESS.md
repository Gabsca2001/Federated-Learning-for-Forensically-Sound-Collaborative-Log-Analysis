# Independent receipt witness: registered-set profile

This opt-in extension adds registration, conservative deadline eligibility and
sealed-set verification to the existing receipt protocol. It does not change
the `provided_client_evidence` profile or reinterpret historical experiments.
Historical evidence retains its original profile. The separately versioned
live handoff is described in [Witness-to-M5 admission](WITNESS_LIVE_ROUND.md);
its validation does not itself revise the manuscript.

## Actors and trust

The client signs its contextual bundle receipt. A separately keyed witness
validates the enrolled client key/level and serializes registration commitments.
A configured RFC 3161 TSA timestamps each commitment and the final closure.
The verifier obtains the witness public key, policy digest, TSA trust store
and final closure digest outside coordinator control. Clients retain signed
acknowledgements for comparison with the final log.

The witness key must differ from the coordinator and client keys. Distinct
keys/processes are testable; independent administration is a deployment
assumption. Run the witness state under a different administrator on a separate
host or separately administered service, without giving the coordinator its
key or write access. Merely putting the service in another local process or
container does not establish that independence.

The TSA is trusted for its signing key and claimed UTC accuracy. Offline
verification checks its certificate chain against the externally supplied,
policy-pinned trust store, the SHA-256 imprint, request/response nonce, policy
OID and explicit signed accuracy. It does not obtain CRLs/OCSP or independently
measure the TSA clock. The accepted PKI validity/revocation policy remains an
operational assumption; historical verification after certificate expiry needs
an appropriate archival validation policy. Do not replace the trust store with
a certificate supplied by the coordinator.

## Commitments and exact deadline semantics

The signed witness policy binds the authenticated round context, coordinator
key, client keys and signing levels, TSA trust-store digest, accepted TSA policy
OID and maximum accuracy. Its digest is the log's initial predecessor.

For registration number `i`, the timestamp subject binds the policy, `i`, the
previous registration digest, canonical receipt hash, signed receipt core
digest and contextual submission identifier. A witness signature binds this
subject, the timestamp-evidence digest and the computed eligibility. Neither
the HTTP request nor any CLI registration option supplies an event time.

Let `[l_i,u_i]` be the verified TSA generation-time interval, `s` the signed
context's issuance time and `e` its exclusive expiry. In the historical v1
policy, `d = e`. The opt-in v2 policy signs `registration_deadline = d` and
requires `s < d < e`, leaving a separate live-admission window. The eligible
registration rule in either profile is:

`eligible(i) iff s <= l_i and u_i < d`.

The deadline event is timestamping the serialized registration commitment,
followed by its atomic journal commit and acknowledgement. It is not the
client's attempted upload time, socket arrival time, completion time of the
HTTP reply, or delivery to the training coordinator. A request started before
the deadline can fail eligibility if timestamping finishes too late.

If the interval lies wholly before opening, mark `before_open`; if its lower
bound is at or beyond `d`, mark `late`; all other non-eligible intervals are
`ambiguous`. These records remain in the journal and are counted separately.
Missing/unspecified accuracy, excessive accuracy and backwards time fail
closed. The actual client-signed timestamp must still satisfy the original
receipt schema/context checks, but it does not determine deadline eligibility.
This follows the uncertainty-interval interpretation in
[RFC 3161, section 2.4.2](https://www.rfc-editor.org/rfc/rfc3161.html#section-2.4.2).

The closure subject binds policy, complete entry count, final registration
digest and the sorted eligible receipt digests. It is timestamped and signed;
its lower time bound must be at or after `d` and not precede the last log time.
After closure, new receipts fail. Identical retries return the stored original
acknowledgement, including after restart/closure. Distinct receipts about the
same submission can be retained without inventing extra numerical contributors.

## Verification and qualified completeness

1. Authenticate the externally pinned policy/context and authority bindings.
2. Verify every client receipt, witness signature and RFC 3161 proof.
3. Reconstruct contiguous sequence numbers, predecessors and unique receipt
   commitments; compute eligibility rather than trusting its stored label.
4. Reconstruct the closure's count, head and eligible set; compare its digest
   with the independently retained final closure pin.
5. Check retained client acknowledgements against the same sequence/digest.
6. Reconstruct inventory intake outcomes from exactly the eligible receipts.

The inventory adapter rejects extra submissions outside the eligible witness
set, omissions, incorrect outcomes and unproved conflict claims. All eligible
receipts for the same contextual submission collapse into one inventory entry.
Two witnessed bundle hashes for one client slot receive the existing conflict
treatment. A missing payload can have a valid negative intake outcome.

Conditional argument: under collision resistance, signature unforgeability,
trusted key/policy/head pins, honest append-only witness operation and accurate
TSA bounds, changing, dropping or reordering a record changes a checked
signature, predecessor, final head, count or eligible-set commitment. Thus the
verified snapshot enumerates all registrations acknowledged in that witness's
sealed history. Comparing its eligible set with the signed inventory exposes
a coordinator omission. This is a manual conditional argument with executable
checks, not a machine-checked proof or a global network-capture theorem.

A signed empty closure can authenticate an empty registered set; it does not
produce positive intake coverage. `coverage_verified` stays false for an empty
evidence set. `deadline_verified` means verified eligibility/closure relative
to the pinned TSA and witness profile. It does not mean all attempts reached
the witness. Availability, censorship, queues, TSA outages and successful
delivery are separate issues. The registration-only verifier does not certify final admission or a model
checkpoint. The separate [live adapter](WITNESS_LIVE_ROUND.md) composes its
closed set with the existing M5 verifier and retains those checks separately.

A malicious witness can sign forks. An independently obtained closure pin
rejects substituted histories; exchanged retained acknowledgements can expose
inconsistent views. This is not a Byzantine transparency consensus or an
automatic global gossip service. The coordinator must not choose all verifier
pins or the apparently external guarantee collapses.

## Operational commands

Use `fl-forensics <command> --help` for complete arguments.

- `witness-enrollment-keys`: export ESK keys/levels from authority-signed
  enrollment records, checking round bindings, validity across the context
  interval and revocation at issuance. The enrollment authority public key
  and coordinator public key are supplied as trusted external inputs. This
  adapter does not obtain a fresh Quote or perform continuous revocation checks.
- `witness-init`: initialize a new witness state, generate its separate key
  and sign the context-specific policy. Default initialization retains v1;
  `--registration-deadline` opts into v2 with a cutoff strictly inside the
  authenticated context validity interval. A client-key manifest maps each client
  to `{"public_key":"relative-or-absolute.pem","trust_level":"swtpm"}`.
  String-only paths explicitly default to `software-development`; they do not
  authorize TPM labels. Use the enrollment export for existing TPM clients.
- `witness-serve`: receive signed receipts at `POST /receipts`; return the
  policy at `GET /policy` and the closed snapshot at `GET /snapshot`. The
  public API cannot close rounds or select a TSA. Non-loopback CLI listeners
  require a configured TLS certificate/key; clients require HTTPS remotely.
- `witness-submit`: register an existing client receipt, verify the reply
  against external keys/policy/TSA pins and retain its immutable acknowledgement.
- `witness-close`: operator-side, after the deadline; write the sealed snapshot
  and print its final digest for independent retention.
- `witness-fetch`: retrieve a snapshot; explicitly reports it as unverified.
- `witness-verify`: require external policy/closure digests and authority inputs;
  optionally reconstruct inventory outcomes and compare retained acknowledgements.

Existing `m5-client-update --client-receipt-root ...` receipts remain valid
inputs. Registration is an explicit opt-in step after receipt creation; the
default client/TPM training campaign is not silently changed to require this
service. Build the selected-profile inventory from the closed eligible set,
then run `witness-verify --inventory ... --submissions-root ...`. This does not
replace final trust/statistical admission verification.

The service uses SQLite immediate transactions with full synchronization,
unique receipt commitments and update/delete guards. Acknowledgements are
returned after commit. Triggers prevent accidental API mutation, not access
by a malicious state administrator. The software witness key/journal are
created with private permissions. The service is a bounded research prototype,
without multi-host failover, WORM storage, global gossip or service-level
availability guarantees. Receipt bodies/HTTP responses have size limits.

## Validation and release boundaries

- `tests/test_submission_witness.py`: signed deterministic-clock protocol
  tests, including deadline uncertainty, replay, retries, concurrency, forks,
  omitted/extra intake entries, conflict and negative-payload outcomes.
- `tests/test_witness_time.py`: actual OpenSSL RFC 3161 signature, imprint,
  nonce, CA, policy and accuracy tests using a disposable development TSA.
- `tests/test_witness_enrollment.py`: authority-pinned enrollment adapter;
  its existing secure-round fixture uses software TPM doubles.
- `scripts/revision_submission_witness.py`: real local TSA, witness in a
  separate subprocess, two timely receipts and one late receipt, sealed log,
  service shutdown and offline verification, coordinator-signed omission and
  truncation negatives. Only public verification evidence is retained.

`results/chain-witness/revision-independent-witness-v2` is the final case for the retained
source manifest. The preliminary v1 case and its distinct sources are
preserved separately. Neither case demonstrates external administration,
an external production TSA, physical TPM custody or complete training admission.

## Opt-in live admission

`witness-round-admit` and `witness-round-verify` require the independently pinned
v2 policy and closure. They bind the sealed eligible intake to actual M5
decisions, coefficients and checkpoint. The original registration-only report
still leaves admission false. See [the complete phase contract, commands,
failure behavior and time assumptions](WITNESS_LIVE_ROUND.md).
