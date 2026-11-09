> Final formal correspondence, 2026-11-03: a concrete graph-identity defect was
> found and corrected. Replayed/borrowed identical bundle bytes now have distinct
> submission-occurrence nodes, preserving their content commitments. Two negative
> regression cases pass; the full corrected-release suite passes 633 tests.
> The 15-property matrix binds assumptions, real function lines/hashes, verifiers
> and evidence. Historical releases and their signed graphs remain preserved.
> See [the final review](../results/revision-final-formal-correspondence-v2/README.md)
> and [current profiles](FORMAL_PROFILE_CORRESPONDENCE.md).

> Concluding review, 2026-11-03: see [FORMAL_MODEL_THEOREMS.md](FORMAL_MODEL_THEOREMS.md)
> for explicit definitions, conditional manual proofs, verifier antecedents and
> the correspondence with the sealed attacked case. Numerical Python code and
> historical signed experiments are unchanged by this documentation review.

# Formal model: correspondence, proof obligations, and scope

Reference: the original `Proposta_modello_formale_derivazione_Gabriele_Scamardo`
proposal, the supplied email approvals, and the receipt/multiround refinements.
This is a manual mathematical review tied to executable checks, not a
machine-checked proof. Tests exercise instances and rejection cases; they do
not prove universally quantified cryptographic or numerical propositions.

## Definitions and refinements

The live scope is weighted FedAvg. Numerical coefficients are defined only for
a positive total mass and a valid contributing quorum. Mandatory-gate
eligibility and actual scoring participation are distinct: scoring can be
skipped for insufficient candidates. A failed transition has no checkpoint and
undefined normalized coefficients, rather than an invented zero model.

Submission IDs refine the original single-bundle-per-client notation. Multiple
conflicting submissions remain individually accounted for and rejected by the
declared intake policy; they do not become multiple numerical contributions.
Runtime admission permits at most one contribution for a client slot.

Provenance, policy treatment, coefficient, and attributed semantic label have
different domains. A valid signature does not prove benignity. Weight zero
does not prove malicious intent. A zero-weight scoring participant can affect
other decisions; a hard-gate failure is excluded from the scoring population
under the ordinary live contract. In the controlled M6 disagreement profile,
observed eligibility and the artificially modified effective policy gate differ:
statistics use observed eligibility before that intervention. Only the observed
gate exclusion is asserted for the population; effective-gate non-compensation
is asserted for the gated-composite numerical decision.

## Original Delta and J

Let K be the ordered set of expected clients in the authenticated context and
R the removed runtime submissions. Both alpha vectors are indexed on K; missing,
protocol-rejected, removed, and other noncontributing slots have zero coefficient
whenever normalization exists. Then

    Delta_K = sum(k in K) |alpha_k - alpha'_k|
    J_K = 1{q_K != q'_K}.

The original proposal left the action of a missing/removed slot unspecified.
The implementation explicitly extends the operational domain with
`not_submitted`. This is padding, not a fabricated trust decision or semantic
judgment. Protocol-rejection histories retain their recorded statuses. The
original measures are emitted in `proposal_metrics` with an explicit profile.
If either aggregate is undefined, Delta_K and the corresponding coefficient
vector are undefined. J remains defined for the recorded operational states.

The older survivor metrics are preserved with their distinct names and
population. With two valid aggregates and no ambiguity in client slots,

    Delta_K = Delta_survivors + sum(s in R) alpha_s.

Proof: the omitted slots have new coefficient zero, the survivor slots give
the survivor sum, and all other slots contribute zero. In particular, frozen
removal of a positive-weight input can yield positive Delta solely through
removal and renormalization. Also, J_K can be one solely because the removed
slot becomes absent. More strongly, every nonempty allowed runtime removal
has J_K=1 under the `not_submitted` padding convention. It is not by itself
evidence of an indirect scoring effect. Survivor action changes and the additional coefficient distance from
frozen-decision renormalization address those separate questions.

## Property correspondence and conditional arguments

| Property | Executable obligation | Assumptions and conclusion |
|---|---|---|
| Separation | Typed dispositions, explicit scoring state and coefficients, separate signed review ledger | Domains are distinct; no implemented inference equates zero weight with a malicious label. |
| P1 Modification detectability | Profile-specific commitment/signature verification; exact canonical encoders, payload hashes and reference bindings | Trusted expected roots/keys, collision resistance and signature unforgeability. Changing a committed core/payload or required reference changes its verified commitment unless a cryptographic assumption fails. A core-preserving alternative envelope representation is not automatically a semantic modification. |
| P2 Submission coverage | Independently supplied client receipts compared with frozen inventory and one consistent final disposition per submission | The comparison detects omission from the supplied witnessed set. It does not establish all submissions ever attempted, coordinator delivery, or deadline eligibility. Empty evidence establishes no nontrivial coverage. |
| P2b Record coverage | `ingestion_coverage`: input enumeration, complete reconstructed identity stream, unique source joins, one terminal outcome per occurrence, and replayed snapshot/outcome bytes | Trusted input commitments/authority and faithful deterministic parsing/transformation under the pinned release. Coverage is relative to I0 committed before this replay, including motivated exclusions and many-to-one consolidation. No claim about pre-ingestion capture. |
| P3 Numerical soundness | Round verifier recomputes trust, collective state, policy, masses, reduced rational coefficients, operational weights/order and checkpoint bytes | Same bound inputs, implementation and numerical environment. Coefficient verification is separate from checkpoint equality, because identical local models can mask changed coefficients. |
| P4 Non-compensation | Mandatory gate precedes the positive policy branches; recomputed factor and mass, then normalized coefficient if defined | For all statistical scores, G=0 implies a=0 and m=n*a=0. If M>0 and quorum holds, alpha=m/M=0. No claim of defined alpha for a failed round. |
| P5 Immutability under review | New signed ledger records reference historical objects; history and subject chains; retry identity and expected-head checks | Append adds records and never edits historical coefficients/decisions/checkpoints. Hashes/signatures detect changes to a known prefix; rollback/fork rejection requires an independently retained expected head. Local storage does not stop an administrator replacing an unanchored history. |
| P6 Multiround blast radius | Authenticated round/product graph, chain validation and typed BFS witnesses | Correctness is reachability in the supplied validated graph. Missing known payloads remain structurally dependent. No global enumeration of every product or proof that declarations capture every internal software dependency. |
| Counterfactual propagation | Rescore diagnostics; separate live trajectories retrain each later client update from the corrected base | Conditional effect under the declared removal schedule, seed, optimizer/data contract and selected horizon. Historical updates trained from the old base cannot substitute for this retraining. No general unlearning, convergence, damage or malicious-intent guarantee. |

For P2b, file hashes fix source byte strings and the profile fixes their record
enumeration. Re-enumeration plus comparison of the entire committed stream
fixes I0, so omitting an input together with its outcome cannot evade verification
by keeping counts equal. The outcome generator visits every occurrence once.
Unique source keys prohibit one occurrence being attributed twice; content
digests and event/window membership validate the joins. Each visit must emit a
retained derivation or an allowed motivated exclusion. Equality with independently
replayed transformation and outcome streams also rejects a correctly signed
but false exclusion/association. Shared event/window targets are permitted, so
the proof does not incorrectly assume a one-to-one transformation.

For P3, mathematical alpha is the rational m/M. Operational aggregation retains
Decimal masses converted to the exact recorded binary weights and uses the
recorded backend input order. Reproduction concerns that operation's serialized
output, not an arbitrarily reordered floating-point sum of rational alphas.
The ideal-arithmetic removal identity and triangle bound remain conditional
statements about the mathematical weighted sum, not certificates for arbitrary
floating-point implementations or altered policy decisions.

For P6, induction on path length shows that traversal finds every reachable
node. Conversely every returned node has a constructed directed path from the
source. The query retains a shortest witness for each reachable set of edge
types; it does not enumerate all paths or multiply scalar weights along mixed
numeric/decision/audit paths. Review edges belong to a separate authenticated
ledger/index and are not traversed by the current campaign query. Structural dependence alone does not show
a nonzero numerical effect or a changed prediction class.

## Validation responsibilities

`test_round_derivation` exercises gate failure, zero-weight scoring participation,
quorum failure, false populations/coefficients/edges, and evidence requirements.
The C and D cases of the four-client example are exercised separately: a failed
gate cannot be compensated; a statistically quarantined input can remain in
scoring and retain a decision path while having no direct numeric edge.
`test_counterfactual_round` checks both metric populations, missing/protocol
slots, undefined normalization, and indirect policy changes from a zero-weight
input. `test_ingestion_coverage` checks duplicate values, many-to-one relations,
sampling exclusions, omissions, duplicate outcomes, false discard reasons,
wrong references, signed false payloads, empty input, and missing evidence.
Review and campaign tests exercise prefix/head integrity, branch isolation,
typed paths, missing artifacts and profile-specific canonical encoders.

The current ingestion extension covers the three named profiles. It is not an
automatic certificate for arbitrary future converters or independent datasets;
those require a declared enumeration, source mapping and exclusion policy.
An independent append-only witness and physical TPM hardware are not produced
by these definitions. Their absence is a scope condition, not evidence of a
property beyond the supplied commitments.

## Required correspondence when updating the thesis draft

The thesis source is deliberately not edited in this increment. The existing
formal draft must later be aligned with the reviewed definitions above:

1. Retain both the original Delta/J on Kreq and the separately named survivor
   metrics; specify the absence marker and undefined-normalization case.
2. Add P2b and its profile-specific I0, motivated exclusions and many-to-one
   mapping. Distinguish an inventory committed before the new replay from a
   separately witnessed claim about its existence in the historical execution.
3. Correct the last explanatory sentence of draft P4: under the declared hard
   gate, G=0 also excludes that input from actual collective scoring. The case
   that can remain in scoring despite alpha=0 is instead a gate-passing input
   later quarantined by the statistical policy. The two cases must not be
   merged in the non-compensation argument.
4. Preserve the ideal-arithmetic scope of the conditional removal identity and
   bound; keep exact operational-backend replay as a separate numerical check.
5. Keep current release and historical TPM release distinct. New analyst-signed
   coverage and metric manifests do not retroactively become freshly attested
   client executions or independently timestamped historical evidence.

The original proposal is the DOCX with SHA-256
`c2ba9b093fdb829ed1252087fc7b0630c8853320e4d3e526759d1800019c09b3`.
The fixed-population measures restore that proposal. The explicit absence
convention and the supported ingestion profiles are implementation refinements;
they are not additional statements attributed to the professor.
