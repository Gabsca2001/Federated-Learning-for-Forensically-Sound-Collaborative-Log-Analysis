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
