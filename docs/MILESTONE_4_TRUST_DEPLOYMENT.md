# Milestone 4 — trust deployment and attestation contract

## Scope

M4 adds the trust plane without changing the UWF-ZeekData24 snapshot, the MLP,
the 15 client partitions, or the clean FedAvg results. The deployment contains
15 independent `swtpm` instances and 15 client services. Every pair has one
persistent TPM-state volume and one Unix-socket volume. A client mounts only its
paired socket; it never mounts TPM state or another pair's socket.

`swtpm` validates multi-node protocol behavior and logical key separation. It
does not provide hardware non-exportability, measured boot of the Docker host,
or protection from a hostile host administrator. The physical adapter uses the
same `tpm2-tools` interface with `device:/dev/tpmrm0` and is a distinct
single-node experiment.

## Identity and key roles

Provisioning creates three different TPM objects at the same persistent handles
inside every independent TPM instance:

- EK `0x81010001`, used only as the provisioning identity basis;
- restricted AK `0x81010002`, used only for `TPM2_Quote`;
- unrestricted ECDSA P-256 ESK `0x81010003`, used to sign application artifacts.

An enrollment request binds `client_id`, `node_id`, TPM instance, EK digest, AK
and ESK public keys, the client TLS CSR, and the measurement-log digest. The ESK
signs the request. The enrollment authority verifies this proof, the declared
one-to-one pair, AK/ESK separation, and the approved baseline before issuing a
signed Enrollment Record and a client-auth certificate.

The emulator has no manufacturer-backed EK certificate. Its enrollment records
therefore state `emulator-logical-identity`; this is not presented as hardware
identity assurance. A physical TPM record requires a manufacturer certificate
or an explicit documented approval.

## Measurement and Quote appraisal

The approved M4 baseline measures the container build contract, swtpm
entrypoint, Acquisition Agent, admission policy, trust policy, and base
experiment configuration. Measurements are extended in order into SHA-256 PCRs
`0,2,4,7,10`. The event log is preserved separately because the final PCR value
is a commitment and cannot reconstruct the measured sequence.

The Verifier signs a five-minute challenge containing a random 256-bit nonce,
PCR selection, policy, baseline, enrollment, node, and client identifiers. The
Attester passes that nonce directly as `TPM2_Quote` qualifying data. Appraisal
uses the enrolled AK public key and independently reconstructed expected PCR
bytes with `tpm2_checkquote`; it does not trust diagnostic PCR values declared by
the client wrapper.

Every nonce is one-use. Repeating the byte-identical evidence is an idempotent
read of the existing result; presenting different evidence for an already
consumed challenge produces `stale`. Failed and successful results are both
preserved and signed by the Verifier.

## mTLS profile

The private experiment CA issues one server-auth certificate to the Verifier and
one client-auth certificate per enrolled client. TLS 1.3 is mandatory. The
client certificate SAN contains `urn:fl-forensics:client:<client_id>`, and its
SHA-256 fingerprint is committed in the Enrollment Record. M4 exercises a real
mutually authenticated handshake and then performs the application identity
binding. A valid certificate from another pair can complete the cryptographic
handshake but is rejected for the claimed `client_id`.

Certificates protect the transport identity; AK and ESK signatures protect the
attestation and artifact roles. These controls are intentionally separate.

## Acceptance gates

The automated suite covers:

- exact 15-pair Compose topology and socket/state isolation;
- AK/ESK key reuse rejection;
- valid Quote appraisal and signed result verification;
- nonce replay with changed evidence;
- altered measurement and PCR-baseline mismatch;
- revoked enrollment;
- AK from the wrong pair;
- TLS 1.3 mutual authentication and wrong client binding;
- quarantine of a batch carrying a failed measurement result;
- idempotent re-verification of identical evidence.

The Docker acceptance run is complete only after all 15 real `swtpm` instances
have provisioned, enrolled, completed mTLS, produced Quotes, and returned 15
`passed` results. Unit tests exercise the same policy logic with software keys
but do not substitute for that runtime gate.

## Execution

```powershell
python -m pip install -e ".[m4,dev]"
python -m unittest discover -s tests -v

fl-forensics m4-verify-deployment --compose compose.m4.yaml --clients configs\clients.yaml
fl-forensics m4-init --workspace artifacts\m4-trust --project-root .
python scripts\run_m4_swtpm.py provision
fl-forensics m4-enroll --workspace artifacts\m4-trust --node-root artifacts\m4-nodes
fl-forensics m4-mtls-test --workspace artifacts\m4-trust --node-root artifacts\m4-nodes
fl-forensics m4-challenge --workspace artifacts\m4-trust --node-root artifacts\m4-nodes
python scripts\run_m4_swtpm.py quote
docker compose -f compose.m4.yaml --profile verify run --rm verifier
```

Stopping without deleting persistent state:

```powershell
python scripts\run_m4_swtpm.py stop
```

Do not append `--volumes` to `docker compose down`: TPM state is part of the
experiment identity and its deletion requires a new enrollment.
