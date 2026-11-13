# Remaining laboratory handover: witness administration

The external TSA can be operated through the existing strict witness profile.
Use `https://timestamp.sectigo.com/qualified`, policy OID `0.4.0.2023.1.1`,
one-second maximum accuracy and the independently pinned root:

`f871f8976b4068d700d5f281084b4a29eaf4b8f35743330ba062fab46f58c2ed`

This is the SHA256 fingerprint of the root certificate DER. The current
canonical PEM trust-store file has SHA256:

`fae4172230777a0f09657739b0e4186e6a73747486baf7768fcb1c3db228018a`

Root identity is published through the provider's official HTTPS disclosure:
<https://secure.sectigo.com/products/PubliclyDisclosedSubCACerts>.
The current provider policy is version 1.1.4, effective 11 February 2026:
<https://www.sectigo.com/uploads/files/eIDAS/Sectigo_eIDAS_TSPPS_v1.1.4.pdf>.
The live endpoint emits explicit signed one-second accuracy, so no policy-
derived default accuracy, insecure TLS fallback or verifier modification is
needed. Keep the pinned public CA and captured chain/CRLs with the case.
Space timestamp requests by at least fifteen seconds as requested by the
provider; account for that latency when choosing the signed registration cutoff.

To complete administrative independence, an actual different trusted operator
must host or control the witness service/account, private key, journal and
backups. The coordinator must not retain privileged access or a private-key
copy. The operator supplies the witness public key/policy digest and final
closure digest to the relying verifier outside the coordinator's channel.

The existing sequence remains:

1. Export the context-bound enrolled ESK keys/levels with pinned authority keys.
2. Have the witness operator initialize a fresh v2 store with a registration
   cutoff inside the authenticated M5 context and the external TSA inputs above.
3. Distribute the policy/key pins before clients register. Retain their signed
   acknowledgements. Use TLS for a remote witness listener.
4. The witness operator closes after the cutoff and distributes its final head
   independently. Complete M5 admission before context/appraisal expiry.
5. Reproduce offline using the recorded CPU image, verify the actual privilege
   separation and preserve the acceptance record described in
   `ADMINISTRATIVE_INDEPENDENCE.md`.

The user currently has no distinct operator resource. Accordingly no independent
host name, operator identity, credential separation or successful laboratory
deployment is asserted here. No external account, payment or message has been
created. A provider timestamp authenticates time; it does not manage the local
witness or replace the separate witness administrator.
