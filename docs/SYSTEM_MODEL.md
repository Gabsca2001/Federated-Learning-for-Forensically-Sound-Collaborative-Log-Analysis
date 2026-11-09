# Common system model and explicit execution profiles

This document indexes and composes the existing formal definitions. It does
not replace the thesis equations, silently change earlier proofs or claim that
every experimental variant is active in one campaign.

## Shared objects and relations

An execution preserves immutable artifacts A, authenticated occurrence identities,
trusted context/policy references, operational decisions, numerical derivations,
and attributed semantic reviews. Equal artifact bytes can occur in different
client/round slots: an occurrence identity remains distinct from a content hash.

The derivation view has three typed relations: numerical use E_num, decision
dependency E_dec and audit/documentation E_audit. The graph endpoints enumerate
the supplied authenticated round/product manifests. M2 source/window lineage
and M8 commitments compose with that view through verified manifest/digest
bindings; the implementation does not materialize every source record and every
possible later product into one globally complete graph.

| Concept | Producer / artifact | Verifier / consumer |
| --- | --- | --- |
| Controlled source occurrence and feature derivation | M2 snapshot; optional signed ingestion inventory/outcome stream | M2 snapshot verification; explicit ingestion coverage verifier when that profile is selected |
| Federated partition and learning contract | M3 partition and snapshot manifests | Partition verifier; context-bound M5 training |
| Registered identity and measured execution evidence | M4 enrollment, challenges, AK Quotes/appraisals, ESK public bindings | Trust gate inside actual M5 admission |
| Client submission occurrence | Client-signed bundle and retained receipt | Receipt coverage and full round verifier |
| Registration eligibility | Signed witness policy, RFC3161 registration intervals, final closure and retained acknowledgements | Witness snapshot/intake/phase verifier with externally supplied expected pins |
| Operational treatment and effective weight | M5 signed decisions, coefficients and checkpoint | Full in-round verifier; witnessed phase wrapper when configured |
| Multiround dependencies and products | Authenticated campaign derivation view | Structure/path verifier; full numerical/product verifiers remain distinct |
| Retrospective semantic judgment | Attributed append-only review ledger | Review verifier with retained expected head; original decisions/weights remain unchanged |
| Direct and later intervention | New counterfactual/retraining derivations | Their named direct or actual-retraining replay verifier |
| Investigative output | M7 prediction, IG/prototypes, ATT&CK hypothesis and report manifests | Transitive M2/M3/checkpoint verification and byte-recomputed products |
| Final preserved evidence set | M8 inventory, Merkle commitment, RFC3161 anchor and recovery archive | Inventory/Merkle/time/recovery/accounting reconstruction under the declared preservation profile |

## Weight and meaning remain separate

For a mandatory-trust plain-FedAvg profile p, the existing mass rule has the
form `m_i = n_i G_i lambda_i(p)`, and normalization is defined only when the
positive-mass/quorum conditions hold. Thus `G_i=0` implies zero numerical mass,
irrespective of the statistical score. The resulting normalized coefficients
describe actual aggregation participation. A failed normalization has no model
or coefficient vector; it is not replaced with a zero-valued successful result.

A statistical-only ablation does not gain the mandatory-trust guarantee.
Clipped/bounded/robust profiles have their declared transformations and, where
applicable, distinct input alpha and final beta coefficients. Their inequalities
are not silently applied to untransformed FedAvg or to later ASR.

The semantic state is a judgment attributed to a reviewer and ledger head.
An admission action or nonzero numerical coefficient does not establish benign
or malicious intent. Later reviews preserve the historical context, decision,
coefficient and checkpoint bytes. A future policy can consume a review only as
an explicitly bound new execution, not by rewriting the past.

## Profiles and their composition

The common model is realized through named contracts. Original TPM-only,
statistics-only, sequential and gated-composite policies remain distinct.
PROTEAN, DBA, baseline adaptations, retrospective groups and bounded/robust
aggregation retain their own inputs, selection rules and empirical limitations.
A frozen shared-input comparison, shadow policy output and separately trained
trajectory are not interchangeable experiments.

The new `unified-witnessed-fedavg-v1` profile selects an actual witnessed M5
campaign, one selected investigative checkpoint, real M7 products and a signed
graph of those declared rounds/products. It requires the same explicit trusted
witness profile for campaign and M7 verification. Every declared round must be
covered; an unknown/missing round or missing witness phase has no legacy fallback.
The supplied profile binds expected policy/closure digests and public verification
inputs. It is an input from the relying verifier, not automatically trusted
because the evidence directory contains a file called "pins".

M7 authenticates the witness closure, eligible inventory, actual admission,
coefficients and phase ordering before inference. It then retains its ordinary
source-lineage, partition, interpretation and reportability gates. The new
`m8-unified-witnessed-chain-v1` profile commits to the resulting declared public
evidence set, timestamps that final commitment, exports deterministic USTAR,
and recomputes the campaign, products, graph and accounting after recovery.
It reuses the existing preservation models, Merkle algorithm, RFC3161 checks
and TAR metadata. Older thirty-round M8 profiles remain unchanged.

## Temporal and trust assumptions

For witnessed eligibility, a valid registration's full TSA uncertainty interval
must lie between issuance and the signed registration cutoff. The cutoff is
strictly inside M5 context validity. The final closure interval must be after
that cutoff and before admission begins; admission must complete before expiry.
Registration/closure intervals have pinned RFC3161 evidence. Admission/completion
times remain signed coordinator-clock claims under trusted execution.

The final M8 timestamp commits to the inventory/Merkle root and cannot precede
the witnessed closure intervals. It is a separate claim from individual receipt
registration deadlines. M8 timestamping alone does not register submissions.

The composition relies on signature/hash assumptions, trusted expected roots,
correct supplied public keys/policies, faithful verifiers and the retained
source/numerical runtime. The software supports a distinct witness operator,
but this local deployment still has a shared administrator. Administrative
independence and independent public-reference custody remain unproved.

## Representative validation scope

The new operational case is deliberately a one-round, fifteen-client, one-local-
epoch software-TPM integration case. It demonstrates the complete selected path
through real M7 and M8. It is not a new attack-efficacy campaign, independent
dataset study or physical-TPM validation. Earlier multiround/retraining studies
remain separately bound evidence for those profiles.

The selected M2 profile verifies the existing canonical snapshot and lineage.
The stronger ingestion-coverage adapter remains an explicit optional profile;
its earlier occurrence-level evidence is not relabelled as freshly replayed in
this case. Global product completeness and capture before the committed input
boundary remain outside the guarantee. All these boundaries are machine-readable
in the new closure rather than inferred from the word "unified".

The manuscript remains frozen. Existing mathematical definitions and historical
signed campaigns are not edited by this implementation step.
