# Formal derivation model: definitions, conditional theorems and proof correspondence

Review date: 2026-11-03, Europe/Rome. This is a **manual mathematical review**,
not a proof-assistant development or independent external certification.
Universal arguments appear below; finite checks and retained experiments support
the correspondence with the program and do not replace those arguments.

The baseline sources are the original formal proposal (SHA-256
`c2ba9b093fdb829ed1252087fc7b0630c8853320e4d3e526759d1800019c09b3`)
and the two supplied supervisor exchanges. Submission-set notation, the explicit
absence marker, experimental gate distinctions and path signatures are stated
implementation refinements. They are not additional requirements attributed to
the supervisor. This review changes maintained documentation, not the thesis,
numerical program, historical signed evidence or experimental outcomes.

## 1. Domain, assumptions and notation

The numerical profile is weighted FedAvg with the declared **gated-composite**
admission policy. Coordinate median, trimmed mean, MultiKrum, Bulyan and the
statistics-only ablation are not given this scalar-weight theorem by analogy.
All inputs needed by a claimed verifier must actually be supplied.

For round t, let K be the finite ordered client set in its authenticated context.
Let U be the set of distinct submission identities admitted to intake accounting.
The implementation identity commits campaign, context digest, client identity
and **bundle byte hash**. Exact retries reuse bytes; distinct signed envelopes
may therefore be distinct submissions even when their model tensors coincide.
Several conflicting submissions of one client receive separate negative intake
dispositions and do not become several numerical contributors for that slot.

For a runtime submission k, use the following distinct objects:

- Gobs(k): all observed mandatory checks pass; this fixes observed eligibility E.
- Geff(k): all effective policy checks pass after any explicitly bound experiment.
- S: the population actually used for collective statistics.
- q(k): operational action; a(k): policy factor; n(k) >= 0: example count.
- m(k) = n(k)a(k): effective mass; A = {k: m(k) > 0}.
- Q(k,r): attributed semantic review at revision r, stored outside the round.

Ordinary execution has Geff = Gobs. In the current implementation S = E when
the eligible population meets the statistical minimum; otherwise S is empty,
the statistical calculation is skipped, and no normalized aggregate is invented.
An eligible but unscored input can have zero mass because the collective minimum
failed. Its operational `integrity_quarantined` status must be interpreted with
that recorded reason, not as proof that its own signature was invalid.

The controlled M6 disagreement experiment is a **separate profile**: it constructs
statistics from observed eligibility and then injects an effective trust veto at
the policy boundary. Thus Gobs = 1, Geff = 0, k in S is possible there. The ordinary
invariant Gobs = 0 implies k not in S remains true; claiming Geff = 0 implies
k not in S for that experiment would be false. Non-compensation below concerns
Geff and still holds for its gated-composite policy. No old experiment is changed
to remove this distinction.

For a scored, effective-gate-passing input, with 0 < rho < 1 and td <= tq:

    a(k) = 1     if Rcomp(k) <= td
           rho   if td < Rcomp(k) <= tq
           0     if Rcomp(k) > tq.

An effective-gate failure or an unscored input has a(k) = 0. Equality at td is
accepted; equality at tq is downweighted when td < tq. The real program compares
finite binary floating-point risks; these boundary statements concern those
recorded values, not an unspecified exact-real reconstruction of risk arithmetic.

Let M = sum m(k). A successful normalized transition requires M > 0 and
|A| >= qmin. Define alpha(k) = m(k)/M there, and zero-pad noncontributing slots
of K. Otherwise alpha and the model are **undefined**, not an all-zero model.

Let B_t be the round's base model and Theta_t its resulting checkpoint model;
B_(t+1) = Theta_t on a validated successor chain. In the original proposal these
are W(t) and W(t+1), respectively. Distinguish

    Theta_ideal = sum alpha(k) u(k)

from Theta_op, the actual backend operation on ordered tensor bytes and recorded
binary weights. Exact rational alpha, operational weight conversion/order and
serialized output are separate obligations.

Every theorem uses its relevant subset of these explicit assumptions:

1. Expected keys, artifact roots and any retained review heads are trusted inputs,
   not inferred from an untrusted artifact's own key field.
2. Hash commitments are collision/second-preimage resistant; signatures are
   unforgeable under the trusted keys. Authorized false statements are not made
   true merely by signing them.
3. Schemas, encoders, parsers, source profiles and the implementation release are
   fixed. Verification consumes stable committed bytes or a checked private copy.
4. Numerical reproduction uses the preserved backend, environment, tensor schema,
   input order and finite, valid numerical inputs. Mathematical identities below
   explicitly concern ideal arithmetic when stated as such.
5. A code/verification argument assumes faithful execution of the inspected
   implementation. It is not a theorem about a compromised host executing arbitrary
   code while reporting a successful verifier result.

**Separation proposition.** The operational/numerical state does not entail a
semantic label. A gate-passing statistical quarantine with alpha = 0 and initial
`not_reviewed` is a valid state; an authorized later review can mark an admitted
positive-weight input `malicious` without changing its historical alpha. The
model admits these counterexamples, so neither zero weight implies malice nor
admissibility implies benignity is a universal rule. Distinct field types alone
would not prove this independence; the admitted states and separate transitions do.

## 2. P1 — detectability of committed modifications

**Statement.** For every object/reference required by a profile and bound to a
trusted expected root, an altered committed representation is rejected, except
with a failure of the commitment/signature assumptions or verifier assumptions.

**Proof.** Follow the authenticated reference chain from the trusted expected
root to the required object. If a required payload changes but its parent
commitment remains fixed, acceptance requires the changed bytes to have the
same commitment, violating the hash assumption. If the parent commitment also
changes, apply the same argument one step toward the root. Eventually acceptance
requires either the original trusted root commitment to collide or a replacement
authenticated statement to be accepted under a key/root not authorized by the
verifier. The key/root checks and signature assumption exclude the latter.
Required-reference deletion is rejected by closure checks. This argument applies
to each finite required chain; it does not cover objects outside the profile.

The committed representation matters. A core signature authenticates the
profile's encoded core; a byte-hash reference authenticates the complete named
file bytes. Equal canonical cores do not imply equal envelope bytes. Conversely,
a core-preserving reserialization is not automatically a semantic modification,
although an existing raw-byte pin may still reject it. M7 mapping/report identities
retain their historical newline-specific encoders.

**Program correspondence.** Signature/root checks in `submission_evidence`,
`round_derivation`, `review_ledger.authenticate_review_subject`, and
`campaign_derivation._pinned`; exact reconstructed-core comparisons in the full
round verifier. This is integrity/authentication, not benignity or capture truth.

## 3. P2 — submission coverage relative to presented client evidence

Let T be a nonempty externally supplied set of valid context-bound client receipt
claims, normalized by submission identity. It is **not** an independently timed,
complete registration log. Let I be the signed inventory.

**Statement.** A covered claim in T must have exactly one consistent inventory
entry. Successful full receipt-bound round verification additionally requires
fully reconstructed intake and exactly one final disposition per inventoried
submission, consistent with its positive or negative intake result.

**Proof.** Unique ordered inventory identities prohibit two entries for one
submission. For every normalized claim the verifier recomputes its identity,
bundle metadata, referenced receipt-core set and reconstructible intake outcome,
then checks that identity in I. Omitting or replacing it fails the identity or
metadata comparison even if the coordinator re-signs I and keeps its entry count
unchanged. Full round binding also requires `inventory_fully_recomputed` and
`intake_outcomes_verified`, rejects an offered context-slot bundle absent from I,
and prevents intake-rejected clients from entering runtime admission. The full
manifest reconstructs one disposition per entry and checks the disjoint client
partition into runtime, protocol-rejected and missing slots. Thus no such entry
can disappear between intake and the final accounted outcome.

For the intake-only API, presented partial evidence may cover its own claims
while extra coordinator entries/outcomes remain unproven. A conflict supported
only by a coordinator extra entry is not proven client equivocation. These
limited reports do not meet the stronger full-binding antecedent.

The theorem cannot detect an omitted claim absent from T and every other trusted
commitment. To see impossibility, compare a history with no submission and a
history with a submission erased together with all evidence available to the
verifier: their observations are identical. Signed client time is a claim within
the context interval, not independent registration time or coordinator delivery.
Empty T yields no nontrivial coverage certification in the API.

## 4. P2b — record-occurrence coverage and many-to-one transformations

Let I0 be the complete stream obtained by the named enumeration profile from
the committed source files. Identity includes source path, record position and
record-content commitment; equal values at different positions remain distinct.
CSV headers are schema, not event occurrences. The named profiles define their
own treatment of blank lines and Parquet rows.

**Statement.** Successful record-coverage verification accounts for every x in I0
by exactly one retained derivation or a reproducible, motivated exclusion. Several
occurrences may map to one event/window; equal counts alone are insufficient.

**Proof.** The verifier reconstructs the complete source identity stream from a
checked private copy of every committed file, and compares both the count and
the full stream commitment. Removing an occurrence together with its outcome
therefore fails even if another occurrence is substituted to preserve the count.
Source joins are keyed uniquely by path and position; duplicate joins fail.
The generator visits every reconstructed occurrence once and emits one terminal
outcome, rejecting uncovered occurrences, mismatched content/event references,
and missing or wrongly assigned retained-window membership. It checks for extra
source links and derived events with no committed source. Shared targets are
allowed, so many-to-one mappings do not require a false bijection. Finally it
re-executes the declared transformation/exclusion policy and compares the entire
snapshot and outcome streams. A correctly signed but fabricated exclusion is
rejected by that replay rather than accepted on the producer's assertion.

This statement is relative to committed I0 and supported source profiles. The
inventory was created before the new verification replay; its independent
existence before the historical processing is not established. Loss before
capture/intake and arbitrary future converters are outside the theorem.

## 5. P3 — normalized participation and operational reproduction

**Lemma.** On a valid normalized transition, alpha(k) >= 0, its positive support
is A, and sum over K of alpha(k) = 1.

**Proof.** All masses are nonnegative, M is their positive sum, and division by
M preserves sign/support. Summing the quotients gives M/M = 1. Padding adds zeros.

**Statement.** Given bound inputs and the fixed deterministic numerical profile,
successful full round verification authenticates and recomputes the declared
policy state, masses, exact rational coefficients, operational ordered weights,
and serialized checkpoint from those inputs.

**Proof correspondence.** The verifier reconstructs observed checks, scoring
population and indicators, then the policy decision cores. It compares each
recorded core with that reconstruction, not just its signature. The derivation
verifier separately checks m = n*a, reduced rational m/M, recorded binary weight,
the ordered positive population and the collective state. `_aggregate_inputs`
repeats the preserved backend operation; the canonical resulting model bytes
must match the checkpoint's committed model. Under deterministic execution,
each of those reconstructed values is the one specified by the fixed program.

Checkpoint equality is **not** an injective certificate of coefficient equality.
For example, u1 = u2 = u gives the same ideal model u for weights (1/4,3/4) and
(3/4,1/4). The real Flower backend also exhibits equal tensor bytes for such an
example. This is why a separately re-signed wrong coefficient must fail its
coefficient check even if the model remains byte-identical.

This argument does not establish benign local training data or equivalence of
arbitrary floating-point evaluation orders with the ideal rational sum. In the
attacked case the clean commitment plus its explicitly bound poisoning transform
defines the actual declared computation; it is not a snapshot-integrity bypass.

## 6. P4 — non-compensation and the gate/scoring distinction

**Statement.** For every statistical score, Geff(k) = 0 implies a(k) = m(k) = 0;
when normalization exists, alpha(k) = 0.

**Proof.** The effective mandatory veto selects the zero-factor branch before
any positive gated-composite branch, independently of the score or trust-risk
mixing weight. Multiplication by n >= 0 gives zero mass. Division by positive M
gives zero alpha. If no valid aggregate exists, alpha is undefined; the theorem
does not introduce a fictitious normalized value for that failure.

In ordinary execution, Geff = Gobs and failed observed gates are excluded before
collective scoring. The converse implications fail: a gate-passing statistical
quarantine can be in S with zero alpha, and a later semantic label is independent
of both facts. The controlled M6 exception described in Section 1 preserves the
effective veto but cannot be used to prove exclusion of its artificial failure
from the already constructed scoring population.

## 7. Fixed-population Delta and J; frozen-removal identities

Let R be the explicitly selected runtime submissions. Map them to their unique
client slots in fixed K. The implemented absence extension is `not_submitted`;
it is an operational padding marker, not a new trust decision or semantic label.
Protocol-rejection histories stay unchanged. When both normalizations exist:

    Delta_K = sum over k in K |alpha(k) - alpha'(k)|
    J_K = 1{the padded operational action vectors differ}.

J is defined even when a normalization is unavailable; Delta then remains null.
Let beta = sum over removed slots alpha(k). Let Delta_survivors denote the same
coefficient distance restricted to remaining runtime slots.

**Lemma 1 (arbitrary valid rescoring).** Delta_K = Delta_survivors + beta and
2*beta <= Delta_K <= 2.

**Proof.** Removed slots have new coefficient zero and contribute beta. All
unchanged missing/protocol slots contribute zero, leaving the survivor distance.
Old survivor coefficients sum to 1-beta; new coefficients sum to 1. The absolute
sum of their differences is therefore at least beta by the triangle inequality.
The L1 distance between two nonnegative unit-sum vectors is at most 2.

**Lemma 2 (frozen decisions).** If beta < 1, survivor masses/factors are unchanged
and the survivor quorum still holds, alpha'(k) = alpha(k)/(1-beta) for survivors
and **Delta_K = 2*beta**.

**Proof.** Survivor mass is (1-beta)M, giving the stated quotient. Each survivor
coefficient increases by alpha(k)*beta/(1-beta); their total increase is beta.
Adding removed mass beta proves the identity. Thus positive Delta alone need not
show an indirect scoring effect: removal and renormalization already explain it.

**Lemma 3 (the explicit absence marker).** For every **nonempty** allowed removal
R, J_K = 1, because at least one runtime-action object becomes `not_submitted`.
This is a direct consequence of the implementation refinement, not evidence of
an indirect policy change. Define J_survivors = 1{`survivor_action_changes` is
nonempty}; the existing list/fraction and
`additional_coefficient_l1_delta_from_rescoring` answer the separate indirect
questions. Preserve the original J field rather than silently reinterpreting it.

The additional rescoring distance is defined only if both the rescored aggregate
and the intermediate frozen-decision aggregate exist. It may therefore be null
even when source and rescored normalization exist. The survivor action-change
fraction is null when there are no survivors; its existing change list still
defines an empty-set Boolean diagnostic. These domains must not be filled with
invented zero denominators or models.

**Frozen model identity and bound (ideal arithmetic).** When the same frozen
conditions and quorum hold:

    Theta_-R = (Theta - sum_R alpha(k)u(k))/(1-beta)
    Theta - Theta_-R = sum_R alpha(k)(u(k)-Theta)/(1-beta)
    ||Theta - Theta_-R|| <= sum_R alpha(k)||u(k)-Theta||/(1-beta).

**Proof.** Split the original weighted sum into removed and surviving terms and
divide the survivor part by 1-beta. Subtract the result from Theta; apply the
triangle inequality and nonnegativity of alpha for any chosen vector norm.
This is not a universal floating-point error bound. Actual serialized differences
are established by backend replay. With zero removed mass, frozen execution
keeps exactly the same ordered positive inputs and hence the same operational
model under the fixed backend. Rescoring may still change other actions or masses.

The formal original proposal did not specify the missing-slot action. Its padding
choice and the resulting degeneracy of J must be explicit in the thesis. They
must not be presented as an automatically informative collusion detector.

## 8. P5 — immutable historical decisions under attributed review

**Statement.** The review transition on a separate ledger appends a new attributed
record and preserves all historical decision, coefficient and checkpoint objects.
A supplied trusted head authenticates its named prefix; requiring an exact trusted
tip additionally rejects a presented tip different from that retained head.

**Proof.** The append API authenticates the pinned historical subject and the
authority's reviewer roster. It requires the current expected predecessor, signs
a record naming the historical commitments plus previous global/subject heads,
and appends it in the separate ledger. It has no transition that overwrites the
referenced historical objects. Exact retry identity returns existing bytes; a
changed operation or stale expected head is rejected. Verification recomputes
canonical record hashes, authorized signatures and both chains in sequence.
Changing a known prefix either breaks a reference/signature or changes the head
named by the trusted external anchor. This also detects a differently signed
authorized alternative prefix when it disagrees with that anchor.

An old anchor certifies its prefix, not a unique future suffix. An internally
valid unanchored truncation/fork may be undetectable. Physical write prevention,
semantic truth, independent review time and verification of merely cited evidence
payloads are not consequences of this ledger theorem. A changed aggregation is
a new derivation, not a historical review mutation.

## 9. P6 — typed multiround reachability and selected-set radius

The implemented runtime graph uses **num, dec, audit** edges. Reviews have a
separately authenticated ledger and lineage index anchored to runtime subjects;
they are not a fourth edge type accepted by the campaign BFS. A conceptual joined
review layer is not silently counted in the current runtime radius.

For a nonempty path p, define signature(p) as the **set of edge types appearing
on p**. Define Prov_sigma(y) by the existence of a path ending at y with exactly
that signature. A homogeneous path is a special case. The original notation
`Prov(dec,y)` must not ambiguously mean both a homogeneous dec path and a mixed
num/dec path: a zero-weight input reaches scoring by num and policy/checkpoint
by dec. The program retains the full edge sequence/signature.

Its display classification is documentary if audit occurs, decision if dec occurs
without audit, and numerical otherwise. This priority classification is lossy;
it does not erase the retained signature. In particular, an audit-labelled path
to a manifest does not prove that its prediction payload is numerically independent.

**Statement.** For a validated finite supplied DAG and a unique known origin s,
the query returns exactly the reachable nodes and one shortest witness for every
reachable (target, exact edge-type set).

**Proof.** Consider the product-state graph (node, mask), initially (s,0), where
each transition follows one real edge and unions its type into the mask. Every
visited state has a constructed real path, proving soundness. For any path, an
induction on length shows that its successive states are visited; skipping an
already visited equal state cannot lose a future transition because all future
possibilities depend only on that node/mask, proving completeness. Unit-length
breadth-first traversal reaches each state at minimum length. The acyclic source
graph excludes return to the origin and gives finite paths; there are at most
eight masks per node. The proof concerns source-graph reachability, not program
semantic dependency completeness or a nonzero numerical effect.

For an explicit nonempty unique submission set R, the set query returns

    Reach(R) = union of Reach(s), s in R.

**Proof.** Each included target has an originating single-query witness; every
single-query target is inserted. Keying targets by occurrence identity counts
them once while retaining origin-labelled paths. This also explains why summing
individual radii overcounts shared descendants.

The constructor validates declared checkpoint-parent pins, consecutive round
indices and parent-model/child-base equality. Model occurrences are keyed by
checkpoint occurrence, so equal model bytes on sibling branches do not merge
their histories. These are declared provenance links; structural verification
alone neither re-executes historical training nor certifies every internal
software dependency. Missing known product payloads remain reachable with
availability annotations. Supplied product-manifest omission fails the pinned
snapshot check; an unregistered or later product is outside that snapshot.

## 10. Controlled counterfactual propagation

Write the declared recurrence schematically as

    u(k,t;sigma) = Train(B_t(sigma), data(k,t;sigma), seed(k,t), optimizer contract)
    Theta_t(sigma) = Aggregate(Admit({u(k,t;sigma)}, fixed policy/trust inputs))
    B_(t+1)(sigma) = Theta_t(sigma).

Here sigma is the explicit intervention schedule, including which client-round
slots are absent and when the client returns. Training data, attacker strategy,
seeds, optimizer reset and other exogenous choices are fixed as declared.

**Statement.** Re-execution of every successor transition from its own changed
base computes that controlled recurrence. In general, old successor updates
cannot establish the same counterfactual trajectory without recomputation or
a separate certificate that they equal the required new-base updates.

**Proof.** Induct on round index: the direct intervention establishes its new
base/checkpoint; each next round receives the previously computed new checkpoint
and evaluates the declared training/admission/aggregation functions, giving the
next recurrence value. Old successor updates instead evaluate Train at the old
base. These functions need not be constant in that argument (e.g. Train(B)=2B),
so reuse can give a different value. This is a statement of general insufficiency,
not a claim that every individual retrained tensor must change in every example.

The single-round counterfactual verifier authenticates historical references and
reproduces the recorded aggregate, but explicitly reports
`historical_policy_decisions_revalidated=false`. Strong claims about source policy
validity require a **separate successful full round verification** under its
preserved release. Historical trust checks remain frozen in that diagnostic;
there is no new Quote or subsequent local training in it. The new attacked case
separately exercised live successor rounds and offline numerical training replay.

Neither this recurrence nor its reproduction proves certified unlearning,
convergence, real-world intent, successful attacker discovery, or general defense
effectiveness. A passing attestation authenticates its declared software/keys,
not the truth of training data. Administrative independence and trusted registration
time require additional mechanisms outside these definitions.

## 11. Connection to the retained attacked case and thesis handoff

The sealed case is identified by closure SHA-256
`f265b12d1d331cdf913eb2c21eab4555684ed79550ab0fd6630bec07d5d6759c`.
Its numerical implementation fingerprint remains
`d38d32f853153b4436801f9402ae52ba336c92c507c949e868b77e1f3b9e6a75`.

- One selected client01 round-1 submission and three selected client01 submissions
  have the same 311-node structural union, reaching five checkpoint models and
  four supplied M7 product manifests. Individual counts for the three sources
  sum to 735. These counts do not define a damage/severity scale.
- First-round positive-weight removal gives Delta_K = 237/3193 and J_K = 1;
  J_survivors = 0 and additional rescoring coefficient distance is zero in both
  direct modes. Both modes reproduce the actual first live intervention model.
- For client11's zero-weight round-3 source, both direct modes give Delta_K = 0,
  J_K = 1, J_survivors = 0 and an unchanged model. Its structural decision paths
  therefore do not by themselves demonstrate an observed numerical change.
- Final model distances differ between the two primary interventions; the two
  reported M7 windows keep their classes while probabilities/attributions differ.
  Complete-trigger ASR is zero throughout this bounded case. This is not a
  successful-backdoor mitigation experiment. Experimental attacker identities
  are supplied ground truth, not automatic detections.

The accompanying review checks use exact rational finite cases, the real policy
and metric functions, a real Flower equal-tensor counterexample, and independent
topological dynamic programming over the sealed typed graph. Finite checks are
labelled as such. The universal arguments are the conditional manual proofs above.

Before the later thesis-writing step, its formal draft must explicitly carry:
observed/effective gates and actual S; undefined failed-round normalization;
both fixed-K and survivor metrics; J's absence-marker consequence; mixed path
signatures and the separate review layer; conditional ideal-arithmetic bounds;
the full-verifier versus structural/authentication-verifier distinction; and
the actual independent-witness, source-profile, hardware and experimental limits.
The thesis is not edited by this review.


## Follow-up: separated influence and successful-attack replay (2026-11-03)

The original fixed-population Delta/J definitions are retained. New versioned
diagnostics distinguish removed weight, survivor action changes, policy total
variation against removal-only renormalization, and direct/additional/total model
distances. Their L2 scalar values are not additive. Historical observed eligibility,
effective gate and scoring membership are exposed separately.

The composed investigation API verifies every supplied graph round with the full
admission verifier before setting its top-level policy-revalidation flag; anchored
reviews and exact intervention/source binding are checked separately. Deadline and
global artifact completeness claims are not strengthened by this composition.

All three historical DBA seeds now have full retraining interventions from before
the attack, with a byte-identical replay control and a clean matched-participation
branch. Both single and group removal yield ASR zero at attack end; this does not
demonstrate extra group synergy, and the single-removal models still differ from
the matched clean models. The original control also recovers ASR zero after clean
training. These software experiments remain distinct from fresh TPM evidence.

See [definitions, results and verification scope](../results/revision-effective-influence-v1/README.md).


## Clean reconstruction and group-analysis follow-up (2026-11-03)

An exact-history comparison API now separates ASR zero from matched clean-reference
equivalence. Ninety reconstructed checkpoints match the intended clean references;
the previous partial removal remains non-equivalent. A pair-conditioned group
pilot uses disjoint clean fitting/calibration and new evaluation training seeds.
Its candidate pool still has false clients and missed membership and is not
validated for automatic exclusion.

A separately qualified same-base execution audit, requiring original unmodified
client snapshots, identifies every experimental execution deviation in the six
evaluation campaigns. Its selected full-history removals match clean references
exactly. This privileged result is not generalized to update-only FL. The full
suite passes 561 tests; the step includes 5,010 local training calls and 300 new
aggregation rounds, all software/analyst evidence. Existing attested evidence and
the thesis remain preserved.

See [profiles, results and remaining scope](../results/revision-clean-reconstruction-and-groups-v1/README.md).


## Incoming-state consistency follow-up (2026-11-03)

The new observable-only audit separates a local update departure from a benign
response to an already affected global checkpoint. It remains statistical evidence,
not semantic truth or a gate override. Frozen evaluation covers changed attacker
identities in IID and non-IID data; ordinary and matched-state clean controls;
all predeclared predictor views; direct effects and complete selected-history
retraining. Primary fusion misses one high-weight non-IID client and has false
candidates, so it is not promoted to automatic exclusion. Exact clean-reference
history equality does not establish that every excluded client was malicious.

See [the frozen study](../results/revision-state-conditioned-audit-v1/README.md) for
all counts, the file-access boundary, calibrations, trade-offs and unresolved scope.


## Prefix-only, round-scoped policy follow-up (2026-11-03)

The experimental `sequential_decision` module separates review from temporary
quarantine. Both score views remain visible. Cumulative evidence uses a fixed
clean-calibrated recurrence and strict round/predecessor bindings. For fixed
calibration and an identical observation/gate/mass prefix, induction on the
deterministic recurrence gives identical prefix decisions regardless of future
inputs. This is a causal-input property, not a theorem about classification
accuracy. The two views are correlated and do not provide independent votes.

Mandatory rejection always gives zero effective mass. Statistical evidence cannot
override it. A changed eligible population invalidates the fixed-cohort detector
and causes review/abstention. Quorum failure never re-admits excluded updates.
Current-round quarantine is neither a permanent ban nor a semantic malice label.
Hash chaining assumes a trusted expected predecessor; the local analyst closure
is not an independent witness, a trusted timestamp or a fresh TPM attestation.
The experimental worker is not wired into live admission and does not validate
invalid-payload handling by the production path.

The 24 reserved episodes, action costs, latency, coverage, ASR trajectories and
clean utility are reported in [the frozen online study](../results/revision-sequential-round-policy-v1/README.md).
It does not replace the approved retrospective candidate-group scope or historical
replay. No automatic repair of previously affected checkpoints is claimed.


## Current-evidence confirmation and statistical release (2026-11-03)

The added `current_evidence_policy` module keeps the previous evidence engine
unchanged and separates its cumulative review evidence from quarantine authority.
For supported gate-compatible current high evidence H, the action is
Q(i,t) = H(i,t) AND H(i,t-1). Hence quarantine is a subset of current high
candidates; a stale cumulative score cannot authorize or prolong it. Failure of
current high evidence releases statistical quarantine immediately. Release does
not override mandatory rejection, prove benign intent or erase prior provenance.
New entry after a gap requires new confirmation. Fixed-calibration deterministic
prefix invariance, strict round order, trusted predecessor and exact-observation
bindings are preserved. Classification accuracy is an empirical question.

The new fixed-protocol study includes changed attackers, short attacks, cessation
and a clean gap between bursts, with shadow proposals counted as well as actual
active actions. The thresholds remain unchanged. All 604 tests pass. This remains
an experimental adapter: no fresh TPM attestation, live admission integration,
permanent ban or automatic repair of earlier checkpoints is claimed. See
[the complete reserved evaluation](../results/revision-current-evidence-policy-v1/README.md).


## Individual clean envelope and evidence retreat (2026-11-03)

The added empirical policy separates client-specific departures from a global
worst-client cutoff. Its additional channel uses positive current minimum excess
over a fixed per-client/view clean envelope, a peak within the uninterrupted
positive episode, and two consecutive observations retaining at least half that
peak. The peak can suppress an action; it cannot authorize one without current
evidence. The final union requires either a confirmed prior current channel or
the confirmed additional channel. Neither a stored peak nor cumulative review
score alone can quarantine an update. Gate rejection remains non-compensable,
unsupported contexts break confirmation, and failed quorum cannot restore
excluded mass. Statistical release is not a semantic benign label.

Geometry-only filtering was rejected empirically rather than silently promoted.
Method selection uses only declared historical development observations. The
new frozen persistent-attack comparison trains all three active/control
histories and counts shadow proposals as well as actual exclusions. All 631
tests pass. Finite empirical accuracy, population false-positive guarantees,
semantic malice and historical clean-state recovery remain separate claims.
No new TPM attestation, live deployment or permanent ban is introduced. See
[the full prospective results](../results/revision-individual-envelope-v1/README.md).


## Final current-release correspondence annex (2026-11-03)

The final correspondence is recorded in [FORMAL_PROFILE_CORRESPONDENCE.md](FORMAL_PROFILE_CORRESPONDENCE.md).
Sections 1–11 above retain the original core/manual arguments and the historical
attested example under its preserved 104-file release. The current 114-file
release adds empirical adapters and diagnostics. Their properties below are
explicitly separate; a matching local function body is not a complete
cross-release numerical certificate.

### Index translation and implementation refinements

Use B_t for the incoming model of round t and Theta_t for its output. The
original proposal calls these W(t) and W(t+1). The later experiment reports
instead use W_(t-1) and W_t, with W0 as the initial checkpoint. Thus the late
round-10 correction starts from B_10 = experimental W9; these are indexing
translations, not distinct execution orders.

The original one-client/one-bundle notation is refined to distinct submission
identities when conflicting signed envelopes exist. They receive separate
negative intake dispositions and cannot occupy multiple numerical slots for
one client. Observed eligibility E differs from the actual scoring population
S if collective statistics are skipped. Controlled M6 effective veto, missing
slot action padding, exact path-type sets, separate review indexing and the
profile-specific committed input stream are also explicit refinements. The
program is not silently claimed to implement a single four-edge-type BFS:
runtime traversal uses num/dec/audit; semantic reviews have a separate
authenticated ledger/lineage index.

### Corrected submission occurrence identity

The review found a graph-construction defect beyond wording refinements.
Content-keyed bundle nodes merged distinct signed receipt claims for the same
bytes. A valid negative intake disposition for a replay in a later round then
caused a cycle; a rejected borrowed-byte claim in the same round inherited the
accepted client's scoring/checkpoint descendants. Both source rounds could
pass full admission verification: the fault was in occurrence modelling.

The corrected release keys every bundle occurrence as
update_bundle:<submission_id>, while its sha256 field still commits the exact
bundle bytes. Base-to-update edges and query origins use that same occurrence
identity. Since submission identity binds context and client as well as bytes,
retries of one identity remain idempotent, while another context/client claim
cannot acquire dependencies merely by reusing content. The graph still checks
acyclicity and exact reference reconstruction. Two regression tests and matched
before/after signed fixtures cover the distinct failure modes.

This is a graph identity profile change recorded by the corrected implementation
fingerprint; numerical admission, local training and weighted aggregation
algorithms are unchanged. Old signed round/graph representations remain under
their preserved source releases. They are neither migrated nor relabelled as
occurrence-keyed graphs by this review.
The preserved attested case has 296 submission occurrences and 296 distinct
bundle-origin nodes, so the newly found alias condition is absent from that
particular case. This survey does not certify every historical graph.

### Additional diagnostic identities

For two normalized survivor coefficient vectors v (frozen decisions) and w
(rescored), define TV(v,w) = (1/2) sum_i abs(v_i-w_i). Nonnegativity and unit
mass give 0 <= TV <= 1. The sum is zero exactly when every coordinate agrees.
This does not establish unchanged raw scores, semantic labels or local data.
For comparable models with representable intermediate arithmetic, define d = Theta_frozen-Theta_original and
p = Theta_rescored-Theta_frozen. Algebra gives total = d+p, but their scalar
norms need not add. For example, local vectors -1, 0, 2 with original weights
(1/2,1/4,1/4) give original 0; removing the first gives frozen 1; selecting
only the zero-valued survivor gives rescored 0. Direct and policy norms are 1,
while the total norm is 0. Recorded finite-precision residuals are numerical
diagnostics, not an exact-real floating-point theorem.

### Current-evidence and individual-envelope invariants

These statements assume fixed calibrated views/cohort, finite validated risks,
valid nonnegative input masses, a faithful state implementation and a trusted
expected predecessor. They concern the adapter's proposed action/mass output,
not fresh TPM admission or automatic operational deployment.

Let s_t be effective support: supplied context support AND all mandatory gates.
Let H_i,t denote s_t and both current standardized view risks strictly above
their fixed global limits. The current-evidence adapter proposes quarantine
exactly when H_i,t AND H_i,t-1. This follows by induction on the streak update:
it increments on H and resets otherwise; streak >= 2 with current H is
equivalent to two consecutive H observations. A gap, unsupported context or
gate failure breaks confirmation. A statistical release does not override a
mandatory rejection or establish benign intent.

For the additional client-envelope channel, let e_i,t be the minimum across
views of current raw risk minus that client's frozen per-view limit. Under
effective support and e>0, P_i,t = max(P_i,t-1,e_i,t); otherwise P_i,t=0.
Let R_i,t mean effective support, e_i,t>0 and e_i,t >= P_i,t/2. Its confirmed
proposal is R_i,t AND R_i,t-1. The final envelope policy uses the union of
this channel and the current-evidence channel. The field named non_receding
means retention of at least half the episode peak; it is not monotonicity
against the previous observation. The stored peak can suppress this channel
but cannot authorize quarantine without current positive retained evidence.
The baseline channel can independently continue to authorize an action.

For either adapter, a mandatory gate failure gives zero proposed effective
mass. Quarantine also gives zero proposed mass. If proposal quorum fails,
the adapter never restores an excluded mass. It emits proposed masses and a
quorum flag, not the original normalized checkpoint proof. In particular,
unsupported-context abstention can preserve positive proposed mass for
gate-passing clients and can leave proposal_quorum_satisfied true. It is
not full statistical acceptance, and the original core rule 'unscored input
has zero mass' must not be transferred to this different adapter. A live caller
must explicitly specify/check its abstention and aggregation contract.

With fixed inputs/calibration, these recurrences and canonical digests are
deterministic. Induction on the equal initial state and equal input prefix
proves identical prefix decisions/heads for any later continuations. This is
causal input use, not statistical independence of the two views. Exact retries
preserve the recorded state; a trusted predecessor is still required to detect
an alternative history. A statistical review queue is not the attributed
semantic review ledger from P5.

There is no universal eventual-quarantine theorem. As a constructive input
counterexample, use global limit 10, per-client limits 2 in both views and
current risks 2.5 followed by 2.0625 in both views. The additional excess is
first 0.5 then 0.0625, while the episode peak remains 0.5; subsequent retention
is false. The baseline stays below its limit. Confirmation never occurs during
the declared 15-round horizon despite positive envelope excess in every round.
This input-level counterexample does not demonstrate a realizable model attack;
it excludes a stronger guarantee not proved by the finite pilot outcomes.

### Complete reference reconstruction and experiment scope

Let C include the starting checkpoint, ordered participation, local snapshots
and declared transformations, per-client seeds, optimizer/reset contract,
training/aggregation implementation and numerical environment. If two executions
share C, deterministic local training gives identical first-round outputs;
identical aggregation gives the same next base. Induction proves complete
history equality. If the common initial base is already contaminated, the same
induction preserves equality to that contaminated-start reference: equality
alone does not establish a globally clean past.

compare_replay_histories checks a projection onto round/base/global/ordered
participant/local-input/local-output commitments. It explicitly does not
authenticate payloads; it does not by itself verify seeds or optimizer state.
Those are caller obligations before interpreting equal projected histories as
the declared execution equivalence. The latest case-specific verifiers check
payloads, inputs, seeds, recurrences and matched references. They are retained
software experiment evidence, not general-purpose live TPM verification.

The historical attested case consists of four five-round trajectories (20 live
round instances total), 300 swtpm Quotes and 296 executed local trainings,
with separately replayed local outputs. It is not one 20-step trajectory, and
its ASR is zero even without intervention. Later 15-round software studies
include successful attacks. In the latest non-IID hard case, late R10 selected
removal leaves validation ASR 1.68% (test 1.54%), while a post-hoc full W0 replay
of the unchanged selected set has ASR zero and exact matched reduced-population
reference equality. Reconstructing the all-client clean history is a separate
privileged unmodified-snapshot intervention. Neither result proves semantic
intent, complete collusion discovery, certified unlearning or physical hardware
security. Ordinary independent-witness/deadline and global artifact completeness
limits remain unchanged.
