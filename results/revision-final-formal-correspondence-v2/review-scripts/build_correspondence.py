"""Current property/assumption/code/verifier/evidence ledger and manual annex."""
from pathlib import Path
import ast
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes

repo=Path.cwd();out=Path(__file__).parent;project=out.parent.parent
lab=repo/'artifacts/revision-formal-correspondence-v2'
def read(p):return json.loads(p.read_bytes())
before=read(out/'before-review.json');current=read(out/'current-obligation-checks.json');historical=read(out/'obligation-checks.json')
correction=read(out/'source-correction.json');current_fp=correction['after_implementation_sha256']
suite=ET.parse(out/'full-tests.xml').getroot().find('testsuite')
assert suite.attrib['tests']=='633' and all(suite.attrib[k]=='0' for k in ('errors','failures','skipped'))
assert current['status']==historical['status']=='passed'
assert current['implementation_sha256']==current_fp
specs=[
('P0','Provenance, operational treatment, numerical weight and attributed semantic state remain distinct.',
 'Definitions and admitted counterstates; neither zero mass nor statistical review proves malice.',
 [('round_derivation','_dispositions'),('review_ledger','append_review'),('lineage','LineageStore.record_review_path')],
 [('in_round_admission','verify_in_round_secure_round'),('review_ledger','verify_review_ledger')],
 ['test_round_derivation.py','test_review_ledger.py','test_review_lineage.py'],['current-full-suite','historical-case'],
 'conditional_core_proof','Core plus separate review layer; statistical review queues are not semantic ledger judgments.'),
('P1','Required committed modifications are detectable relative to authenticated expected roots.',
 'Trusted keys/roots; collision/second-preimage resistance and signature unforgeability; fixed encoders, stable bytes and faithful verifier execution.',
 [('round_derivation','_verify_signature'),('campaign_derivation','_pinned'),('review_ledger','authenticate_review_subject')],
 [('in_round_admission','verify_in_round_secure_round'),('campaign_derivation','verify_campaign_derivation')],
 ['test_round_derivation.py','test_campaign_derivation.py','test_review_ledger.py'],['current-full-suite','historical-case'],
 'conditional_core_proof','Only required representations. An optional missing product payload remains structurally represented with availability annotations.'),
('P2','Every presented authenticated receipt claim has one consistent inventory entry; full round binding also accounts for final dispositions.',
 'Nonempty externally supplied receipt set, correct context/enrollment and expected authority; exactly reconstructed inventory/intake for full binding.',
 [('submission_evidence','verify_submission_coverage'),('round_derivation','_binding_core'),('round_derivation','_dispositions')],
 [('submission_evidence','verify_submission_coverage'),('in_round_admission','verify_in_round_secure_round')],
 ['test_submission_evidence.py','test_submission_evidence_workspace.py','test_round_derivation.py'],['current-full-suite','historical-case'],
 'conditional_core_proof','Intake-only coverage is narrower than admission verification. No independent registration deadline, delivery or universal set of attempted submissions.'),
('P2b','Each enumerated committed record occurrence has a reproduced derivation or motivated exclusion, including many-to-one outputs.',
 'Named enumeration/transformation profile, fixed committed source files and replay; path/position/content identities remain distinct for equal values.',
 [('ingestion_coverage','_records'),('ingestion_coverage','_outcomes')],
 [('ingestion_coverage','verify_ingestion_coverage')],['test_ingestion_coverage.py'],['current-full-suite','initial-formal-review'],
 'conditional_core_proof','Relative to supplied I0; historical pre-transform existence and pre-capture completeness are not independently timestamped.'),
('P3','Reconstructed policy, masses, rational coefficients, ordered operational weights and checkpoint bytes agree under the declared backend.',
 'Successful mass/quorum domain, authenticated inputs, preserved implementation/environment/order; n is the bound declared count, not proof of semantic data truth.',
 [('in_round_admission','_compute_statistical_state'),('in_round_admission','_runtime_decision_core'),('in_round_admission','_aggregate_inputs'),('round_derivation','materialize_round_derivation')],
 [('in_round_admission','verify_in_round_secure_round')],['test_round_derivation.py','test_in_round_campaign_accounting.py'],
 ['current-full-suite','current-finite-checks','historical-case'],
 'conditional_core_proof','The original gated-composite live FedAvg profile. Graph-only checks and newer empirical adapters do not automatically satisfy this full antecedent.'),
('P4','Effective mandatory veto forces zero factor/mass; normalized alpha is zero when a valid aggregate exists.',
 'Gated-composite veto branch, nonnegative count, positive total mass and quorum for alpha. Distinguish observed and experimentally injected effective gates.',
 [('composite_admission','decide_admission_policies'),('in_round_admission','_runtime_decision_core'),('round_derivation','_dispositions')],
 [('in_round_admission','verify_in_round_secure_round')],['test_composite_admission.py','test_round_derivation.py'],
 ['current-full-suite','current-finite-checks','historical-finite-checks'],
 'conditional_core_proof','Observed gate failure excludes from ordinary scoring. Controlled M6 effective veto can be injected after the observed scoring population was formed.'),
('Delta-J','Original fixed-K L1 Delta and binary J remain distinct from survivor/rescoring diagnostics.',
 'Two valid normalizations for Delta; zero-padding on fixed K; not_submitted action padding. Frozen mass formula requires beta<1 and survivor quorum.',
 [('counterfactual_round','_proposal_metrics'),('counterfactual_round','_calculate')],
 [('counterfactual_round','verify_counterfactual_round')],['test_counterfactual_round.py'],
 ['current-full-suite','current-finite-checks','historical-finite-checks'],
 'conditional_core_proof','Delta_K>=2 beta; frozen Delta_K=2 beta. Every nonempty allowed removal gives J_K=1 under this explicit absence convention.'),
('DIAG','Survivor policy TV and vector/model differences measure separate effects.',
 'Validated normalized coefficient vectors and matching survivor population; comparable models with representable intermediate arithmetic. Caller binds model/weight/source correspondence.',
 [('influence_diagnostics','influence_diagnostics')],[('investigation_verifier','verify_investigation')],
 ['test_influence_diagnostics.py','test_investigation_verifier.py'],['current-full-suite','current-finite-checks','effective-influence'],
 'conditional_diagnostic_definition','TV is zero iff the two normalized coefficient vectors agree. Model L2 scalars do not add; zero TV need not mean unchanged raw scores.'),
('P5','Appending attributed review preserves historical decisions/coefficients/checkpoints and authenticates anchored prefixes.',
 'Authorized keys, fixed historical subject, application append/lock semantics and independently retained expected head for rollback/fork protection.',
 [('review_ledger','append_review'),('review_ledger','_read_history'),('lineage','LineageStore.record_review_path')],
 [('review_ledger','verify_review_ledger')],['test_review_ledger.py','test_review_lineage.py'],['current-full-suite','historical-case'],
 'conditional_core_proof','An old head authenticates its prefix, not a unique future suffix. No physical write prevention, trusted review time or truth of a semantic label.'),
('P6','Typed BFS returns precisely supplied-graph descendants, shortest witnesses per exact edge-type set, and deduplicated selected-set union.',
 'Validated finite supplied DAG, known unique origins, three runtime edge types and authenticated round/product manifests; trusted expected graph snapshot.',
 [('round_derivation','_graph'),('campaign_derivation','reconstruct_campaign_graph'),('campaign_derivation','structural_blast_radius'),('campaign_derivation','structural_blast_radius_set')],
 [('campaign_derivation','verify_campaign_derivation')],['test_campaign_derivation.py'],['current-full-suite','historical-finite-checks','historical-case'],
 'conditional_core_proof','Submission-occurrence v2 separates repeated bytes across contexts/client slots. Old snapshots retain their original release. Review is separate; radius is structural exposure, not damage, semantic guilt or all products ever created.'),
('COMPOSE','Full source admission, graph, exact removal set and optional externally anchored attributed reviews can be verified together.',
 'Full inputs for exactly all graph rounds; matching pinned authorities/sources/intervention population; retained review tip when review evidence is supplied.',
 [('investigation_verifier','verify_investigation')],[('investigation_verifier','verify_investigation')],
 ['test_investigation_verifier.py'],['current-full-suite','effective-influence'],
 'conditional_verifier_composition','No new Quote, successor training, trusted deadline, global product inventory or product-payload recomputation follows from composition.'),
('CF','A declared successor counterfactual requires fresh training from each changed base, or an independent equality certificate.',
 'Fixed intervention, data/attacker schedule, seed/optimizer/environment/backend and starting checkpoint; preserve source releases and branch order.',
 [('counterfactual_round','_calculate'),('retraining_replay','_replay')],
 [('counterfactual_round','verify_counterfactual_round'),('retraining_replay','verify_retraining_replay')],
 ['test_counterfactual_round.py','test_retraining_replay.py'],['current-full-suite','historical-case','group-validation'],
 'conditional_recurrence_proof','Standalone round-local counterfactual preserves historical_policy_decisions_revalidated=false. The latest case-specific software verifiers cover their explicit transforms, not a generic live TPM replay.'),
('REF','Matched clean-reference reconstruction requires complete declared execution equality, not ASR zero alone.',
 'Authenticated payloads and independently checked participation, initial/warm checkpoint, local input commitments, seeds, optimizer and environment.',
 [('remediation_validation','compare_replay_histories')],[('remediation_validation','compare_replay_histories')],
 ['test_remediation_validation.py'],['current-full-suite','group-validation'],
 'conditional_reference_induction','The API compares a projection of committed histories; it explicitly does not authenticate payloads or independently verify seeds/optimizer. Case verifiers must supply these antecedents.'),
('STAT','Current/evidence-envelope actions are deterministic functions of their validated input prefix; mandatory veto remains non-compensable.',
 'Fixed calibrated cohort/views/thresholds, valid inputs, strict predecessor/round bindings and faithful state execution. Caller handles the proposal and quorum.',
 [('sequential_decision','SequentialRoundPolicy.step'),('current_evidence_policy','CurrentEvidencePolicy.step'),('client_envelope_policy','ClientEnvelopePolicy.step')],
 [('sequential_decision','SequentialRoundPolicy.step')],
 ['test_sequential_decision.py','test_current_evidence_policy.py','test_client_envelope_policy.py'],
 ['current-full-suite','current-finite-checks','envelope-study'],
 'conditional_adapter_invariants','These are proposals, not the original full live-admission proof. Unsupported inputs may retain eligible proposed mass; no guaranteed eventual quarantine or classification accuracy.'),
('GROUP','Clean-calibrated pair groups and individual anomaly sets remain retrospective hypotheses with measured errors.',
 'Externally justified clean references, separate cohort/fit/calibration/evaluation, frozen rules, authenticated observations and post-selection labelled controls.',
 [('group_calibration_v2','fit_group_reference'),('group_calibration_v2','calibrate_group_threshold'),('group_calibration_v2','detect_conditioned_groups')],
 [('group_calibration_v2','detect_conditioned_groups')],['test_group_calibration_v2.py','test_retrospective_groups.py'],
 ['current-full-suite','group-validation'],
 'empirical_discovery_scope_not_universal_accuracy','V2 misses a member in every priority group of the added six cases; an accurate envelope prefix set is not a pairwise proof of collusion.')]

evidence_specs={
 'current-full-suite':out/'full-tests.xml','current-finite-checks':out/'current-obligation-checks.json',
 'historical-finite-checks':out/'obligation-checks.json','initial-formal-review':project/'output/formal-review-20261103/review-manifest.json',
 'historical-case':project/'output/attack-replay-20261103/case-closure.json',
 'effective-influence':project/'output/effective-influence-20261103/completion-closure.json',
 'baseline-validation':project/'output/baseline-dba-closure-20261103/completion-closure.json',
 'occurrence-probe-before':out/'borrowed-bundle-probe-before.json',
 'occurrence-probe-after':out/'borrowed-bundle-probe-after.json',
 'historical-occurrence-scope':out/'historical-occurrence-scope.json',
 'group-validation':project/'output/group-validation-20261103/completion-closure.json',
 'envelope-study':project/'output/geometry-detector-20261103/completion-closure.json'}
evidence={name:{'path':str(p),'sha256':sha256_file(p)} for name,p in evidence_specs.items()}
def node_for(path,name):
    tree=ast.parse(path.read_text());parts=name.split('.')
    n=next(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n.name==parts[0])
    if len(parts)==2:n=next(n for n in n.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==parts[1])
    return n
def function_ref(module,name):
    path=repo/'src/fl_forensics'/f'{module}.py';node=node_for(path,name)
    asthash=lambda n:hashlib.sha256(ast.dump(n,include_attributes=False).encode()).hexdigest()
    legacy=lab/'historical-runtime/fl_forensics'/path.name
    try:unchanged=asthash(node_for(legacy,name))==asthash(node)
    except (OSError,StopIteration):unchanged=None
    return {'path':path.relative_to(repo).as_posix(),'function':name,'line':node.lineno,'end_line':node.end_lineno,
        'source_sha256':sha256_file(path),'function_AST_sha256':asthash(node),'local_AST_equal_to_historical_function':unchanged}
ledger=[]
for identifier,statement,assumptions,code,verifiers,tests,ev,status,limits in specs:
    for n in tests:assert (repo/'tests'/n).is_file(),n
    ledger.append({'id':identifier,'statement':statement,'assumptions':assumptions,'status':status,
        'implementation':[function_ref(*x) for x in code],'verifiers':[function_ref(*x) for x in verifiers],
        'test_source_sha256':{n:sha256_file(repo/'tests'/n) for n in tests},'evidence_ids':ev,'boundaries':limits,
        'proof_assistant_certified':False})
(out/'property-code-evidence-matrix.json').write_bytes(derived_json_bytes({'profile':'final-property-code-evidence-correspondence-v2',
    'implementation_sha256':current_fp,'before_correction_implementation_sha256':before['implementation_sha256'],
    'manual_conditional_proofs':True,'evidence':evidence,'properties':ledger}))
md='# Final property → assumptions → code → verifier → evidence matrix\n\n'
md+='Corrected current implementation: `'+current_fp+'` (114 package files). Before graph correction: `'+before['implementation_sha256']+'`. Historical attested core: `'+historical['implementation_sha256']+'` (104 files). Function-body comparison is local AST equality, not a proof of transitive or cross-release execution equivalence. The JSON ledger binds actual line locations and file/function hashes.\n\n'
md+='| Property / status | Assumptions and scoped result | Implementation / verifier | Tests / evidence |\n| --- | --- | --- | --- |\n'
for r in ledger:
    f=lambda x:'`'+Path(x['path']).stem+'.'+x['function']+'`:'+str(x['line'])
    md+='| '+r['id']+' — '+r['status']+' | '+r['statement']+' '+r['assumptions']+' **Boundary:** '+r['boundaries']+' | '+', '.join(map(f,r['implementation']))+'; verify: '+', '.join(map(f,r['verifiers']))+' | '+', '.join('`'+t+'`' for t in r['test_source_sha256'])+'; '+', '.join(r['evidence_ids'])+' |\n'
md+='\n## Evidence identities\n\n'
for name,item in evidence.items():md+=f"- **{name}**: `{item['path']}`; SHA-256 `{item['sha256']}`.\n"
md+='\nFinite tests/experiments support correspondence, not universal classification accuracy. Signed analyst records do not certify proof-assistant correctness, independent time, witness administration or physical TPM hardware. The thesis remains unchanged.\n'
(out/'PROPERTY_CODE_EVIDENCE_MATRIX.md').write_text(md)

annex='''

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
'''
(out/'CURRENT_RELEASE_PROOF_ANNEX.md').write_text(annex.lstrip())
theorems=repo/'docs/FORMAL_MODEL_THEOREMS.md'
assert sha256_file(theorems)==before['document_before_sha256']['FORMAL_MODEL_THEOREMS.md']
theorems.write_text(theorems.read_text()+annex)
profile='''# Final formal-profile correspondence

Date: 2026-11-03. This is a manual conditional proof and implementation review.
The original proposal and accepted mail obligations are preserved as read-only
references. The current release, historical attested release and newer empirical
adapters have distinct scopes. The complete source/line/hash/evidence ledger is
in the [review package](../results/revision-final-formal-correspondence-v2/README.md).

'''+md
(repo/'docs/FORMAL_PROFILE_CORRESPONDENCE.md').write_text(profile)

refinements=[
 ('Submission accounting','One received bundle/decision per client','Distinct conflicting submission identities are all accounted for negatively, with a unique numerical client slot.'),
 ('Actual scoring population','S equals gate-passing clients','S equals observed eligibility only when collective statistics run; otherwise it is empty. Controlled M6 effective veto is separately profiled.'),
 ('Typed review','A conceptual review edge joins the formal graph','A separate authenticated review ledger/index is implemented; the runtime radius query traverses only num/dec/audit.'),
 ('Delta/J','Fixed-K L1 coefficient distance and binary action change','Both are restored with explicit not_submitted padding; J=1 for any nonempty allowed removal is not indirect-effect evidence.'),
 ('I0 chronology','Inventory committed before transformation','Complete source enumeration and transformation replay are checked; independent pre-historical-processing time is not established.'),
 ('Weighted reconstruction','Same values imply same weighted checkpoint','Exact rational coefficients and operational ordered backend bytes are separately verified; equal models do not identify weights.'),
 ('Review immutability','Application append preserves history','Externally retained heads protect known prefixes/tips; no unique future suffix, physical write prevention or semantic truth follows.'),
 ('New policies','Later empirical strengthening','Fixed-input-prefix and hard-veto invariants are separate from classification accuracy and from full live TPM admission.')]
ref_md='# Implementation refinements and open boundaries\n\n| Topic | Original/stronger reading | Exact current correspondence |\n| --- | --- | --- |\n'
for row in refinements:ref_md+='| '+' | '.join(row)+' |\n'
ref_md+='\nThe first seven rows are explicit correspondence refinements, not newly attributed instructions from the professor. An independent administratively separate timed witness and a unified four-edge-type runtime traversal are not implemented by the presented profiles. The accepted receipt threat-model discussion is retained; no stronger guarantee is inferred.\n'
(out/'REFINEMENTS_AND_BOUNDARIES.md').write_text(ref_md)

formal_sources=[n for n in before['thesis_sources'] if 'formal' in n.lower()]
handoff='''# Thesis handoff after final correspondence review

The actual thesis sources remain unchanged. Formal draft files in the frozen
source inventory: '''+', '.join('`'+n+'`' for n in formal_sources)+'''.

The next writing pass must use the current correspondence table and carry these
points explicitly:

1. Explain the corrected submission-occurrence identity and preserve the source
   release of old signed graphs. Use one model-index convention; translate incoming B_t/output Theta_t,
   proposal W(t)/W(t+1) and experiment W_(t-1)/W_t once.
2. Distinguish factor a, mass m=n*a, normalized alpha and undefined failure
   domains. Preserve observed/effective gate and actual scoring distinctions.
3. Retain original fixed-K Delta/binary J and the separately named survivor,
   TV and model diagnostics; explain absent-slot padding and frozen Delta=2 beta.
4. Keep mixed exact edge-type signatures, separate review indexing and the
   supplied-manifest boundary of structural radius. A scalar path product is
   not an influence coefficient on a mixed provenance path.
5. State receipt coverage relative to externally presented evidence, and record
   coverage relative to committed named-profile I0. Do not claim independent
   delivery, deadline registration, capture completeness or historical timestamp.
6. Bind P3/full historical-policy claims to the full round verifier and its exact
   preserved release. Graph-only, round-local and projected-history APIs have
   narrower obligations. Record the caller's payload/seed/optimizer checks.
7. Present 20 attested round instances as four five-round trajectories, with
   emulated hardware and the unsuccessful bounded attack. Keep successful
   15-round software DBA studies separate, including the latest controlled
   late-removal and full-rewind results and their different populations.
8. Report negative baseline outcomes, FedGradTrace literal-equation failure,
   V2 false pools/missing members, differing clean-reference information budgets
   and the labelled secondary/post-hoc status of the newer evaluations.
9. Separate new empirical policy proposals from the original live gate policy.
   Preserve unsupported-context mass semantics, lack of eventual-quarantine
   guarantee and the unresolved adaptive/live-TPM validation.
10. Update the assistance disclosure to reflect this revision workflow: it now
    includes AI-assisted code, experiment execution/verification and analysis
    support as well as drafting/translation. The earlier translation-focused
    wording cannot automatically describe all later work. The author should
    review and state the actual contributions accurately in the writing pass.

ToN-IoT remains deferred at the user's request. Baseline consolidation and the
declared retrospective group checks are completed as bounded studies with
negative outcomes retained; perfect detection was not an accepted requirement.
This handoff is not a thesis edit or proof-assistant certification.
'''
(out/'THESIS_HANDOFF.md').write_text(handoff)
report='''# Final formal correspondence closure

The accepted formal core is supported by explicit conditional manual arguments,
current source/verifier bindings and retained evidence. The review also found
and corrected a concrete graph-identity defect. Local training, admission
arithmetic and aggregation algorithms are unchanged. The thesis and historical
corpus/TPM evidence are preserved.

The [property/assumption/code/verifier/evidence matrix](PROPERTY_CODE_EVIDENCE_MATRIX.md)
covers separation, authenticated modification detection, submission and record
coverage, numerical soundness, non-compensation, original Delta/J, separated
influence diagnostics, anchored review, multiround radius, composed verification,
controlled successor replay, matched reference and empirical adapter/group scope.
The JSON ledger binds every named function to real line locations and source
hashes. Universal statements use the [manual current-release annex](CURRENT_RELEASE_PROOF_ANNEX.md)
and the preserved core proof note; finite checks do not replace those arguments.

## Checks completed now

- All **633 tests pass**, zero failures/errors/skips, two existing Typer warnings.
  The initial 631-pass run is preserved separately; it did not cover the defect.
- The current release passes 3,750 real policy boundary cases, 4,650 frozen
  fixed-K metric cases, 3,780 rescored cases and 3,900 ideal removal identities/
  bounds; undefined normalization is checked separately.
- Each of the two newer action adapters passes 16,384 transitions against a
  separately computed oracle and 512 equal-prefix/different-future pairs.
  Exact retry and quorum non-readmission cases are checked.
- The historical 104-file release is loaded separately from its authenticated
  source archive. Its 4,135 shortest typed witnesses on the 1,678-node graph,
  three sealed radius reports and four counterfactual metrics are checked again.
  It is not relabelled as the current 114-file numerical release.

## Clarifications carried into the proof scope

### Concrete implementation defect corrected

The old graph keyed bundle nodes by content hash. Two signed claims for the
same bytes could therefore merge across rounds or client slots, even though
one was correctly rejected by intake. A rejected cross-round replay caused a
cycle; a same-round borrowed-byte claim acquired the other client's scoring and
checkpoint descendants. The latter occurred even though source and graph
verifiers accepted the old representation.

The fix uses **update_bundle:<submission_id>** as occurrence identity and keeps
the bundle hash as its content commitment. Campaign origins and base-to-update
edges use the same identity. Two regression cases cover both scenarios, using
real signatures/intake with a simulated numerical backend. The old-release
counterexamples are retained alongside the successful current-release checks.
See `source-correction.json` and `submission-occurrence-fix.patch`.
The preserved attested graph was checked separately: its 296 submission
occurrences have 296 distinct bundle-origin nodes. The alias defect is absent
there; that observation is not an exhaustive certificate for all old graphs.

### Claims kept distinct

1. The original scalar-weight/gated-policy theorem is not a complete certificate
   for FLAME, coordinatewise robust rules, literal FedGradTrace or newer adapters.
2. The current statistical adapters can abstain while leaving eligible positive
   proposed masses and quorum true. This is not full statistical acceptance or
   the core live path's unscored-zero-mass rule. Live integration needs an explicit
   caller contract; no operational guarantee is added here.
3. Current/peak-retention invariants prove prefix use and current-evidence
   requirements, not accuracy or eventual quarantine. The retained synthetic
   peak-suppression counterexample excludes that stronger conclusion.
4. The history comparator authenticates neither payloads nor the seed/optimizer
   contract on its own. Case verifiers establish those additional antecedents.
   Same-start unmodified equality can preserve an already contaminated base.
5. Reviews use a separate authenticated layer, while runtime BFS has three edge
   types. Fixed-K J is always one after nonempty allowed removal under the explicit
   absence marker; neither fact should be silently reinterpreted in the thesis.
6. The 20 attested round instances are four five-round trajectories. Later
   successful software DBA/reconstruction studies have different profiles and
   stronger empirical outcomes, not retroactive fresh TPM evidence.

These are explicit [refinements and boundaries](REFINEMENTS_AND_BOUNDARIES.md),
not new professor requirements or a proof that every desired stronger claim
holds. Receipt deadline/delivery, independent witness administration, global
artifact completeness, physical TPM and semantic truth remain outside the
demonstrated guarantees. The original proposal and two mail sources are pinned
in `before-review.json`, with original-language reference text preserved.

## Result and next boundary

The graph-construction correction is included in the final reviewed release.
The core arguments remain conditional on the stated hypotheses and verifier composition. The newer
empirical rules retain their narrower proved invariants and measured limitations.
The package is a local software analyst record, not external mathematical
certification. The exact two package-source changes and one regression-test
change are bound in the final closure; all other package files, historical
evidence, thesis sources and Git index are preserved and checked.

The [thesis handoff](THESIS_HANDOFF.md) specifies the later text changes, including
model indexing, source profiles, negative results and an accurate assistance
disclosure. Before live automatic-policy claims, adaptive and live-TPM integration
work remains. ToN-IoT stays deferred. No thesis text is changed in this step.
'''
(out/'FORMAL_CORRESPONDENCE_CLOSURE.md').write_text(report)
print('CURRENT FORMAL MATRIX AND MANUAL ANNEX BUILT',len(ledger),len(report),flush=True)
