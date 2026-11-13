# External TSA adoption: verified technical result and remaining administration

A fresh one-round experiment registers fifteen genuine software-TPM-signed
client submissions through the local witness and the real HTTPS Sectigo
`/qualified` timestamp endpoint. Fifteen eligible submissions are admitted by
the existing TPM-only M5 policy. The fifteen registration tokens and one closure
token verify with the unchanged strict core: SHA256 imprint, signature chain,
nonce, policy OID `0.4.0.2023.1.1` and explicit signed one-second accuracy.

The root DER SHA256 is
`f871f8976b4068d700d5f281084b4a29eaf4b8f35743330ba062fab46f58c2ed`.
It was cross-checked against the provider's official HTTPS CA disclosure, rather
than trusted because it appeared in a timestamp response. Actual token signers
and their intermediate pass signature, validity and authenticated cached CRL
checks at audit capture. This does not guarantee future revocation status.
The provider's current policy v1.1.4 and disclosure hashes are retained in
`results/chain-witness/revision-external-tsa-v2/external-authority/provider-and-negative-controls.json`.

The witness process stops before M5 admission. A relocated public package
reconstructs the closed eligible set, intake dispositions, actual admission
decisions, coefficients and checkpoint using the pinned CPU image with network
disabled. The public package excludes private witness/coordinator keys and TPM
private state. External TSA contact is unnecessary for that reconstruction;
we do not control or stop the external provider.

Coordinator-signed omission, truncated history and an incorrect retained final
head are rejected. Seven separate timestamp negative controls also reject
different content, wrong policy, too narrow an accuracy budget, nonce replay,
token mutation, unrelated CA and unrelated public-TSA chains.

## Timing, preserved interruption and version correspondence

The first attempt is retained in
`artifacts/revision-external-tsa-20261105-v1`. Training consumed approximately
126 seconds of its signed 300-second registration window. Ten registrations
were eligible; client11 was correctly marked late. No admission or completed
round is claimed for that attempt, and no signed deadline was edited.

The successful v2 case uses a new context, witness key, journal and software-TPM
state. Its 450-second cutoff is signed before training inside the unchanged
600-second M5 context. Requests are spaced by at least fifteen seconds following
the provider's published request limit. The closure is obtained after the cutoff;
actual admission completes before context expiry. Admission/completion times
still rely on the signed coordinator clock, not independent TSA observations.

All 127 core modules match the actual pinned image and retained source manifest.
The existing full suite passed 752 tests for that unchanged implementation.
The new host controller passed static checks and is retained separately;
it is not represented as TPM-measured. The exact CPU image remains necessary
for strict numerical replay. This is a one-round protocol pilot, not a new
multi-seed attack campaign or production-performance evaluation.

## What remains genuinely unproved

The TSA is external, but the receipt witness remains controlled by the same
local operator as the coordinator. The user confirmed that no separately
managed trusted resource is available. Administrative independence and external
retention of the policy/final-head pins are therefore **not demonstrated**.
A process, container, extra local account or rented host under the same
privileged operator would not close that condition.

The laboratory handover and honest pending acceptance record are included.
A distinct operator must control witness credentials, private key, journal and
backups and distribute public policy/head references outside the coordinator's
control. Once available, the same experiment and actual privilege/access tests
must be executed there. Witness honesty/availability remain assumptions;
registration does not establish network delivery to the coordinator.

The `/qualified` endpoint name is not our assessment of legal qualification,
institutional acceptance or compliance. No such assessment is claimed.

No thesis source, figure or PDF was edited in this task. ToN-IoT remains deferred.
Historical campaigns, source releases and the closed development register on
port 8765 remain preserved.

## Evidence and official references

- `validation.json`: actual counts, verifier outcomes and source bindings.
- `external-token-audit.json`: all sixteen authenticated token intervals/certificates.
- `relocated-public-verification.json`: complete disconnected reconstruction.
- `omission-verification.json`, `truncation-verification.json`,
  `wrong-closure-pin-verification.json`: actual evidence negatives.
- `laboratory-handover.md`, `administrative-acceptance.json`: remaining deployment.
- [Provider timestamp service and request spacing](https://www.sectigo.com/resource-library/time-stamping-server).
- [Current provider policy](https://www.sectigo.com/uploads/files/eIDAS/Sectigo_eIDAS_TSPPS_v1.1.4.pdf).
- [Official CA SHA256 disclosure](https://secure.sectigo.com/products/PubliclyDisclosedSubCACerts).
