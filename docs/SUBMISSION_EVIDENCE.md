# Signed submission evidence and intake coverage

This increment implements client receipts, immutable client/submission copies,
signed input inventories and a verifier relative to supplied client evidence.
It corresponds to R04–R06 and the first part of R03 in the revision plan.

It does not yet implement the full derivation manifest, final admission-decision
coverage, an independent witness service, reviews or multiround blast radius.

## Client production

The existing `m5-client-update` command accepts an optional
`--client-receipt-root PATH`. Supplying it enables receipts for that invocation.
Use a separate client-owned directory for each round, outside the submission
directory. The existing profile remains available when the option is absent;
old campaigns are not silently upgraded to stronger guarantees.

The client first preserves its signed bundle, then signs a receipt binding:

- campaign, context digest, round and client;
- starting model and previous checkpoint;
- bundle file hash and separately the signed bundle-core digest;
- a claimed submission time and signing level, under a versioned signed domain.

The receipt is saved beside the bundle as `submission-receipt.json` and under
the client receipt root as `<submission_id>.json`. An identical retry reloads
and verifies the existing signed bytes. Either missing copy can be restored
from the other. Diverging copies cause failure and are not overwritten.

Receipt creation uses the current client time by default, not the old bundle's
generation time. It must not be used to claim historical delivery. Existing
receipt recovery is possible after expiry without creating a new time claim.
The TPM signing adapter is the existing one; unit/integration fixtures using
software keys do not constitute a new TPM campaign.

The receipt commits the final bundle bytes. The existing experimental
post-training attestation rebind is explicitly blocked from replacing a bundle
once its receipt exists. Complete any such rebind before committing the final
submission, or represent a later change as a separate derivation. Never rewrite
the old receipt to fit a new bundle hash. That combined live workflow remains
outside this first increment.

## Build and verify an inventory

Supply a directory containing only this round's exported client receipt copies.
These copies constitute T; do not reconstruct T solely from the coordinator's
remaining submission folders. The verifier obtains client keys from the signed
enrollment records bound to the authenticated round context, rather than from
keys embedded in the submissions.

```bash
PYTHONPATH=src python -m fl_forensics m5-input-inventory \
  --workspace ROUND_WORKSPACE \
  --trust-workspace TRUST_WORKSPACE \
  --client-receipts CLIENT_EVIDENCE_FOR_THIS_ROUND \
  --submissions SUBMISSIONS_ROOT \
  --inventory NEW_INVENTORY_PATH

PYTHONPATH=src python -m fl_forensics m5-input-inventory-verify \
  --workspace ROUND_WORKSPACE \
  --trust-workspace TRUST_WORKSPACE \
  --client-receipts CLIENT_EVIDENCE_FOR_THIS_ROUND \
  --submissions SUBMISSIONS_ROOT \
  --inventory NEW_INVENTORY_PATH
```

For creation, `--coordinator-workspace` can select the existing shared campaign
authority. Once written, the inventory is not re-signed on retry. Changed
evidence or payloads are verified against the old inventory, not silently
incorporated in a new history.

Each unique submission has an explicit intake outcome:

- `ready_for_admission`: bundle/update/metrics integrity checks passed;
- `rejected_missing_payload`: at least one required payload is unavailable;
- `rejected_invalid_payload`: bytes, signature or context checks failed;
- `rejected_conflict`: different bundle hashes for one client/context are
  supported by multiple supplied client receipts.

These are intake outcomes, not the final trust/statistical admission decisions.
Two identical receipts do not create two contributions. Two different bundles
remain separate, accounted-for submissions and are conservatively rejected at
intake when both are evidenced.

## Meaning of the verification report

`verified_for_evidence_set` and `coverage_verified=true` mean that the supplied
client evidence is accounted for in the signed inventory, including negative
intake outcomes. An inventory can legitimately contain submissions outside a
presented subset T. Those entries are listed and are not client-authenticated
by that subset. `inventory_fully_recomputed` is true only when all entries and
all referenced receipt cores were reproduced from the supplied evidence.

A coordinator's extra entry alone does not prove client equivocation. If an
intake rejection depends on a second receipt that is not supplied, the report
lists an unverified outcome and sets `intake_outcomes_verified=false`.

An empty T returns `insufficient_evidence`. Missing or inconsistent covered
entries return `invalid`, even if a coordinator re-signs a self-consistent
inventory after removing the original input.

The following fields remain false in this profile:

- `deadline_verified` and `delivery_verified`: client signatures/time claims
  are not independent delivery or registration timestamps;
- `admission_decisions_verified`: no final admission/checkpoint claim is made.

The signing-level claim is covered by the receipt signature and the workspace
adapter compares it with enrollment. This is not verification of a fresh TPM
Quote. Full admission still uses the existing secure-round verifier.

The caller must retain a trusted context, enrollment authority and coordinator
key. A local filesystem does not provide independent witnessing or anti-rollback
by itself. Intake availability is checked from the files provided at verification
time; missing historical files prevent reproduction of the original availability
claim.

## Validation before thesis claims

Run the targeted cryptographic tests, workspace/CLI integration tests and the
existing regression suite. Retain the logs and describe software fixtures as
such. The first thesis result supported by this increment is coverage relative
to an explicit evidence set. Claims about complete admission, multi-round
effects or witnessed deadlines require their later increments and experiments.

## Opt-in independent registration extension — 4 November 2026

The separately named `independent_witness_rfc3161_v1` profile adds a separately keyed service, RFC 3161 registration intervals, a complete signed closure and externally pinned set/inventory verification. The original supplied-evidence APIs and their false deadline/delivery flags remain unchanged. This is a new opt-in implementation, not a retroactive upgrade of historical evidence. Its complete assumptions, conditional argument, enrollment adapter and actual local test boundaries are in [INDEPENDENT_SUBMISSION_WITNESS.md](INDEPENDENT_SUBMISSION_WITNESS.md). The final public integration evidence is in `../results/revision-independent-witness-v2`; 44 new tests and the complete 730-test suite pass. No independent external administration, new TPM campaign or complete final-admission guarantee is claimed.
