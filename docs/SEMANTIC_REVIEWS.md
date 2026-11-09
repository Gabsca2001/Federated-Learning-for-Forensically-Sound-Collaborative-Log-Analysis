# Signed semantic reviews and append-only history

The review module adds judgments attributed to an author over an already
preserved historical derivation. The subject is a **submission in a particular
context and round**, identified by its manifest and commitments. A label does
not automatically become a permanent classification of the entire client.

Review does not modify operational decisions, weights, checkpoints, or the
historical `semantic_state="not_reviewed"` field. The current view is built
separately from review history. If a different aggregation or new training is
needed, its result must be a new derivation.

This increment addresses R07. Its lineage fragments provide an index useful
for subsequent links; they are not themselves a multiround blast-radius query
or a causal demonstration.

## Artifacts and authorities

For initialization and append, the ledger must be outside the historical round
directory; this constraint is checked again after relocation. It contains:

- `ledger.json`: signed genesis with the manifest hash, context, and authorized
  reviewer roster;
- `review-ledger.jsonl`: one canonical signed line per review;
- `lineage/`: a derived, reconstructible index of audit/review links;
- `.append.lock`: a temporary lock for cooperating writers.

Each record retains the submission, manifest and final-disposition digests,
decision/checkpoint references when available, author, label, reason, evidence,
claimed time, and `operation_id`. It has both a global sequence and a subject
revision, committing to the previous global record and previous record for the
same submission.

The ledger authority signs the initial roster; individual reviewers sign their
judgments. Verification requires public keys supplied by a trusted source:

- the coordinator key for authenticating historical documents;
- the authority key for authenticating genesis;
- a reviewer identity → public key mapping, checked against the signed roster.

A new author's signature does not itself authorize that author. The roster is
not silently extended, and this module does not provide key rotation. The CLI
uses software ECDSA keys from PEM files and the signed `software-development`
profile. This does not demonstrate a fresh Quote, a TPM operation, or an updated
attested machine state.

## Append, concurrency, and retries

The caller supplies the **expected previous head**. Under the lock, the module
authenticates history, compares that head with the current tip, and appends a
line only if they agree. A stale head does not authorize another append. Two
writers with the same expected head cannot both append normally to the same
history.

`operation_id` stably identifies an operation. A retry supplies the same data
and the head preceding that operation: it reads the already signed record,
without creating another revision or generating another ECDSA signature.
Reusing the identifier for different data is an error. The result contains the
preserved record and current head, which may have advanced if other reviews
have since been appended.

The signed line is the primary history. A subsequent indexing failure returns
`lineage_indexed=false` and `lineage_index_error`, while retaining the committed
record. Retrying the same operation can rebuild the index without changing
JSONL bytes. The index does not determine signature, authorization, or anchor
validity.

## Trusted head, prefix, and tip

A head contains `ledger_id`, `genesis_sha256`, `sequence`, and
`last_record_sha256`. It is a history commitment to retain through a trusted
channel or procedure outside the ledger copy being checked. It is not a fresh
timestamp attestation or, by itself, an additional signature.

Verification distinguishes:

| `anchor_status` | Meaning |
|---|---|
| `unanchored` | The supplied chain is internally verifiable but lacks an external trusted head |
| `trusted_prefix` | History contains the expected prefix; subsequent records are not covered by that anchor |
| `trusted_tip` | The expected head matches the supplied tip |

With `trusted_prefix`, `rollback_protection_verified=true` concerns the prefix
identified by `anchored_sequence`; `current_tip_anchored` remains false.
`require_tip_anchor=true` accepts only `trusted_tip`. A shorter history or a
branch not containing the expected head fails verification.

Without an external anchor, an internally valid rollback or fork may remain
undetected. Observing one branch does not reveal every possible alternative.
**A different directory does not automatically make a head independent**:
custody, access, and reference origin matter. The CLI prevents exporting a head
inside the ledger but does not certify the chosen storage's independence.

## Meaning of judgments and evidence

Allowed labels are `not_reviewed`, `benign`, `suspicious`, `malicious`, and
`inconclusive`. The reason must be nonempty, and at least one evidence reference
with a SHA-256 digest and description is required.

`semantic_states` shows the latest attributed judgment per submission, with its
revision number and author. Authors can disagree, and earlier judgments remain
in the chain. The latest view is not consensus, ground truth, proof of malicious
intent, or proof of causal responsibility.

The module signs evidence **references** without retrieving or verifying their
payloads: `evidence_payloads_verified=false`. The analyst must check the content
and relevance of cited material. The timestamp is also a signed claim:
`review_timestamps_attested=false`. Revision order follows the chain and
sequences; independently attested wall-clock time is not inferred.

## Historical authentication and numerical reconstruction

`authenticate_review_subject` uses the same byte snapshot for pin verification
and decoding of the manifest and referenced artifacts. It verifies signatures,
context, commitments, and inventory/scoring/decision/checkpoint/model links.
The initial manifest pin must come from an already verified, retained reference:
hashing a replaceable copy does not itself create a trusted root.

The report keeps these claims distinct:

- `historical_artifacts_authenticated=true`: the supplied historical documents
  match the checked signatures and references;
- `historical_round_recomputed=false`: review has not numerically re-executed
  the round under the current code.

The derivation fingerprint binds the package code. Numerically reconstructing
a historical version after project changes requires its preserved source
release and environment, as described in `ROUND_DERIVATION.md`. The review
module does not bypass a version mismatch or rewrite the historical manifest
to match the current verifier.

## Module API

| Function | Result and main precondition |
|---|---|
| `authenticate_review_subject` | Authenticate the historical round against its manifest pin and coordinator key |
| `initialize_review_ledger` | Create or read consistent subject/roster genesis and return the current head |
| `append_review` | Check author, subject, and expected head; append or recognize a retry |
| `verify_review_ledger` | Read-only verification of chain, signatures, links, and relationship to an optional trusted head |

Public verification does not acquire the write lock and can operate on a
read-only export. If it encounters an incomplete snapshot during concurrent
append, it fails conservatively and can be repeated after the writer finishes.

## CLI example

Run from the repository checkout with its dependencies and `PYTHONPATH=src`,
avoiding another editable installation of the project. Prepare the following
example layout first; key files must already exist and be authorized under
the chosen procedure.

```text
campaign/round-001/                  historical round; do not modify
reviews/round-001/                   separate ledger
trusted/coordinator.public.pem      historical coordinator key
trusted/review-authority.public.pem  ledger authority key
trusted/analyst-1.public.pem          first reviewer key
trusted/analyst-2.public.pem          second reviewer key
trusted/reviewers.json               roster with paths relative to this file
private/review-authority.private.pem authority private key
private/analyst-1.private.pem         first reviewer private key
evidence/review-001.json              evidence references
anchors/                            heads retained outside the ledger
```

The name `trusted` is organizational only: key authenticity and anchor custody
are operational assumptions, not properties of a directory name.
For example, `trusted/reviewers.json` contains:

```json
{
  "analyst-1": "analyst-1.public.pem",
  "analyst-2": "analyst-2.public.pem"
}
```

`evidence/review-001.json` is a list. Replace the placeholder with the actual
digest of the reviewed material; the module does not verify its payload:

```json
[
  {
    "sha256": "INSERT_64_HEXADECIMAL_CHARACTER_EVIDENCE_SHA256",
    "description": "Description of the material and its relevance to the review"
  }
]
```

Set `MANIFEST_SHA256` to the trusted historical 64-character hexadecimal pin
and `SUBMISSION_ID` to the identifier in that manifest. Replace the following
placeholders before execution:

```bash
MANIFEST_SHA256='INSERT_MANIFEST_PIN'
SUBMISSION_ID='INSERT_SUBMISSION_ID_FROM_MANIFEST'

PYTHONPATH=src python -m fl_forensics review-init \
  --ledger reviews/round-001 \
  --round-workspace campaign/round-001 \
  --manifest-sha256 "$MANIFEST_SHA256" \
  --coordinator-public-key trusted/coordinator.public.pem \
  --authority-private-key private/review-authority.private.pem \
  --reviewer-keys trusted/reviewers.json \
  --export-head anchors/round-001-head-000.json

PYTHONPATH=src python -m fl_forensics review-append \
  --ledger reviews/round-001 \
  --round-workspace campaign/round-001 \
  --coordinator-public-key trusted/coordinator.public.pem \
  --authority-public-key trusted/review-authority.public.pem \
  --reviewer-keys trusted/reviewers.json \
  --expected-head anchors/round-001-head-000.json \
  --operation-id round-001-review-001 \
  --submission-id "$SUBMISSION_ID" \
  --reviewer-id analyst-1 \
  --reviewer-private-key private/analyst-1.private.pem \
  --label suspicious \
  --reason "Analyst rationale tied to the referenced evidence" \
  --evidence evidence/review-001.json \
  --export-head anchors/round-001-head-001.json

PYTHONPATH=src python -m fl_forensics review-verify \
  --ledger reviews/round-001 \
  --round-workspace campaign/round-001 \
  --coordinator-public-key trusted/coordinator.public.pem \
  --authority-public-key trusted/review-authority.public.pem \
  --reviewer-keys trusted/reviewers.json \
  --expected-head anchors/round-001-head-001.json \
  --require-tip-anchor
```

JSON results distinguish `initialized`, `appended`, and `verified`; errors
produce exit code 1. An export failure **after** a committed append can also
produce code 1 while retaining `status="appended"`, the head, and
`head_export_error`. Do not infer from exit code alone that no record was
written: retry the same idempotent operation and inspect the result.

Export uses write-once semantics and does not silently replace a different head
in the same file. An export path inside the ledger is rejected before
initialization or append. After new reviews, choose distinct anchor filenames
and retain them according to the threat model.

## Failures and explicit recovery

Append-only is a verifiable application rule, not physical protection against
the filesystem administrator. This module does not use WORM storage or an
independent production ledger.

If a writer exits leaving `.append.lock`, the code does not automatically break
the lock. Before manual intervention, establish that no writer is active,
preserve the supplied state, and compare it with retained anchors.

A partial, noncanonical, removed, or inconsistent JSONL line makes verification
fail. No automatic truncation or repair occurs. Recovery must be documented,
preserving original bytes and using a backup or an explicit new representation
of verified history; do not silently delete the failing portion. This module
does not provide an automatic log-recovery command.

A missing lineage index is different: the signed record may remain valid, and
retry can reconstruct the index. A new complete preservation package should
include the relevant ledger and anchors; review does not update or rewrite
historical packages.
