# Closed-witness registration followed by live M5 admission

This opt-in profile connects an authenticated eligible receipt set to actual
M5 trust/admission decisions, effective coefficients and the reconstructed
checkpoint. It uses `witness-init --registration-deadline ...`,
`witness-round-admit` and `witness-round-verify`. The default M5 deployment and
the historical `provided_client_evidence` and witness v1 profiles retain their
original behavior. It does not deploy an automatic exclusion defense.

## Roles and phase contract

The witness registers receipts; the federated coordinator admits contributions
and aggregates. A separate key and process do not demonstrate independent
administration on a shared computer. External witness/TSA authority, policy
and closure references remain deployment assumptions, as described in
[the registration protocol](INDEPENDENT_SUBMISSION_WITNESS.md).

Let `s` be context issuance, `e` context expiry and `d` the registration cutoff.
Witness policy v2 signs `d` and requires `s < d < e`. The original v1 continues
to use `d = e`; it cannot be passed to the new live-admission adapter.

For a verified TSA interval `[l,u]`, eligibility requires `s <= l` and `u < d`.
The complete registration chain is closed only when its closure timestamp's
lower bound is at least `d`. The new adapter requires the closure's whole
interval to precede its admission start, and completion before `e`:

`d <= closure.lower <= closure.upper <= admission.start <= completion < e`.

The new cutoff is a distinct signed policy field, not a coordinator-provided
timestamp at submission or admission. An unpinned replacement policy, a cutoff
outside the context, an uncertain boundary, a timestamp outage or late closure
fails the applicable checks. The CLI has no admission-time override.

**Time qualification:** registration/closure intervals are verified RFC3161
evidence under the pinned TSA. Admission/start/completion times are signed
coordinator-clock claims, checked by the implemented runtime. They are not
new TSA proofs of execution time or protection against a compromised host
backdating its clock. This remains the trusted live-execution assumption.

## Execution and verification

1. Prepare the normal partitions, enroll the clients, verify their fresh TPM
   Quotes, and issue an authenticated M5 context containing the admission
   contract. For the measured pilot the policy is explicitly `tpm_only`.
2. Export enrolled ESK keys and levels with `witness-enrollment-keys`, using
   independently supplied authority and coordinator public keys.
3. Initialize a new witness store with `--registration-deadline` inside that
   context's validity interval. Authenticate and distribute its key, policy
   digest and TSA trust store before client training/registration. A new store
   must not reinterpret the old closed demonstration.
4. The existing `m5-client-update --client-receipt-root ...` path trains and
   signs both bundle and receipt using the client's ESK. The explicit
   host-side `witness-submit` adapter authenticates the policy and verifies the
   returned acknowledgement. Client containers remain network-disabled.
5. The witness operator closes the log after the cutoff and retains the final
   digest through the accepted independent channel. Retrieve and verify the
   entire closed set, not a coordinator-selected subset of receipts.
6. Run `witness-round-admit` with the snapshot, both external digest pins,
   trusted keys/CA, the M5 workspace, trust workspace, authorized validation
   split, delivered submissions and the coordinator signing workspace. Its
   full options are available through `--help`.
7. The adapter verifies the closed set and context, builds exactly its eligible
   intake inventory, freezes the supplied evidence and invokes the existing
   receipt-bound M5 admission/derivation code. Late or unregistered payloads
   cannot enter its submission set. Eligible missing, invalid or conflicting
   inputs retain their negative intake outcome; the derivation gate blocks
   non-ready clients before scoring. It never substitutes an intake outcome
   for a final trust or contribution-policy decision.
8. The existing M5 verifier recomputes trust, actions, weights and checkpoint.
   The adapter checks phase completion and signs a `witness_live_round_receipt`
   binding context, policy, closure, inventory and checkpoint digests. The
   emitted files are under the round's `witness-round/` directory.
9. Run `witness-round-verify` with the same independent inputs. It revalidates
   the timestamps, eligible set, inventory, frozen evidence, phase bindings,
   actual decisions, coefficients and model. No running witness or TSA is
   needed for this verification.

`registration_set_verified`, `deadline_verified`, `coverage_verified`,
`phase_order_verified`, `admission_decisions_verified` and
`coefficients_verified` describe separate checks in this combined report.
The intake-only verifier still leaves final admission false. Neither report
turns registration into a universal network-delivery guarantee;
`delivery_verified` remains false. Actual processed payloads have their own
digest-bound intake/admission evidence.

## Numerical reproduction boundary

The relocated public package verifies using the exact preserved CPU image.
A host attempt outside that image differs by one unit in the last place in
one raw statistical indicator (0.12465515702709776 versus
0.12465515702709777). The strict decision comparison rejects that attempt.
The host Torch build reports 2.14.0 and the image reports 2.14.0+cpu; matching
module hashes alone do not establish numerical-runtime equivalence. The
diagnostic is retained without changing signed data or introducing a tolerance.
Use the executed source release and pinned runtime for exact reconstruction.

## Failure and replay behavior

An empty eligible set cannot certify positive completeness. A complete negative
intake decision for an eligible unavailable payload does not authorize its use.
A valid receipt does not override a later revocation or expired trust result.
Insufficient contributors produce no completed checkpoint for this profile.

The existing M5 code can write intermediate decisions or a checkpoint before
a later completion-time check fails. Such a computation receives **no completed
witness-round receipt** and fails this profile's offline verifier. Do not
present an isolated intermediate M5 checkpoint as a successful witnessed round.
The implementation does not provide an all-files crash-atomic publication
transaction or automatically resume every partially completed execution.

After a completed receipt exists, an identical retry verifies the preserved
historical result instead of admitting new inputs or renewing the context.
New inputs require a new authenticated context/store. Verification requires
the matching preserved source/runtime release; old signed evidence is never
re-signed to appear bound to a newer implementation.

## Reproduction

The fresh local campaign is orchestrated by
`scripts/revision_witness_round.py`, with a cached-base image defined in
`Dockerfile.revision-witness` and separate witness federation/trust/admission
configurations. The controller uses new TPM state and a new case workspace,
and stops only its own witness/TSA processes and TPM containers. The previous
development witness at port 8765 remains a separate closed historical store.

The campaign uses two independent one-round cases, fifteen actual `swtpm`
clients, genuine TPM ESK signatures/Quotes and a real local-development RFC3161
authority. Its negative case withholds a payload component, leaves one client
unregistered, registers another late and revokes an otherwise ready client.
This is protocol validation, not a poisoning-resistance or accuracy benchmark.
An external production TSA and independent administrative control remain
unvalidated. The original failed controller attempt is preserved separately;
its successful nominal result alone is not the completed two-case release.

See the source-bound results in `results/chain-witness/revision-witness-round-v2` once its
summary and independent audit both report `verified`. The executed image's
complete source/config/controller release is retained with those results.
