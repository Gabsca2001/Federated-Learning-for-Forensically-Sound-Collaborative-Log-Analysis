"""Freeze the secondary group validation before selection or interventions."""
import zipfile
from group_common import *
from fl_forensics.round_derivation import implementation_sha256

assert not LAB.exists();LAB.mkdir()
previous=PROJECT/'output/baseline-dba-closure-20261103'
assert sha256_file(previous/'completion-closure.json')=='6ecb9bf6d30527cc55c61b9a5bfc60dce315bf10df244937068b3864091efa69'
old=read(previous/'completion-closure.json')
for name,value in old['core']['artifacts'].items():assert sha256_file(previous/name)==value
with zipfile.ZipFile(previous/'source-and-study-scripts.zip') as archive:
    files={n:archive.read(n) for n in archive.namelist() if n.startswith('src/fl_forensics/') and n.endswith('.py')}
assert len(files)==114
for name,value in files.items():assert (REPO/name).read_bytes()==value
assert implementation_sha256()==old['core']['current_implementation_sha256']
source_closures={
    'artifacts/revision-geometry-detector-v1/study-artifact-closure.json':'608ed58b2bb8f47ba2ec4c7610a9504ebd3320788c5247f6eb391fbb798b702f',
    'artifacts/revision-sequential-round-policy-v1/study-artifact-closure.json':'9f4a6809b6543fd3f58782a085b3fc40c041c19d039cf4fb64659b7fd0188e07',
    'artifacts/revision-state-conditioned-heldout-v1/study-artifact-closure.json':'815ad0dea39d82860acde8310734a2e8945522c142fc29d1d909c88208623fbe'}
for name,value in source_closures.items():assert sha256_file(REPO/name)==value
fit={'iid':[f'artifacts/revision-dba-three-seed-v1/clean-s{s}' for s in (341593,342593,343593)],
    'non-iid':[f'artifacts/revision-state-conditioned-heldout-v1/private-generation/non-iid/fit-{s}' for s in (411593,412593,413593)]}
cal={'iid':[f'artifacts/revision-sequential-round-policy-v1/private-calibration/iid/cal-{s}' for s in (451593,452593,453593)],
    'non-iid':[f'artifacts/revision-sequential-round-policy-v1/private-calibration/non-iid/cal-{s}' for s in (454593,455593,456593)]}
tasks=[t for t in read(SOURCE/'reserved-execution-before-training.json')['tasks'] if t['branch']=='shadow-FedAvg']
protocol={'profile':'retrospective-group-validation-v1','status':'Secondary fixed-method analysis of previously evaluated histories, not a new untouched prospective population.',
    'previous_completion_sha256':sha256_file(previous/'completion-closure.json'),'implementation_sha256':implementation_sha256(),
    'source_closures':source_closures,'fit':fit,'calibration':cal,'evaluation_tasks':tasks,
    'selection_horizon':10,'intervention_round':10,'continuation_rounds':[11,12,13,14,15],'minimum_contributors':8,
    'primary_method':'Unchanged pair-conditioned group V2, fitted/calibrated separately by cohort, with the original scale floor .05 and strict maximum-clean-campaign threshold.',
    'primary_group_choice':'Rank all maximal cliques by descending weakest standardized edge, then lexicographic client tuple. Select the first clique retaining at least eight clients; preserve all oversized cliques and never prune one using truth. Empty output stays empty.',
    'secondary_method':'Union of clients quarantined at least once by the frozen individual-envelope policy in rounds 1–10. This is an anomaly-selected set, not a pairwise collusion detector. Preserve singletons and empty sets.',
    'selection_boundary':'Separate feature-only selector receives neutral aliases, deltas, tensor shapes, server-validation indicators and frozen past/current decisions. No private rows, identity plan, ASR or later frames enter selection. This is a documented data-flow boundary, not an OS/Docker isolation claim.',
    'direct_controls':'Each selected set, each member individually, and up to twenty hash-seeded uniformly sampled benign size-matched sets plus the benign size-matched set with closest original sample mass. Truth is used only after selection to identify benign controls, not to choose candidates or efficacy.',
    'continuation_controls':'For each nonempty feasible selected set: joint removal, each member alone, closest-mass benign set and first predeclared random benign set. Deduplicate identical removals across methods. No-intervention replay for all six attacked histories.',
    'intervention_semantics':'R10 reaggregation uses preserved local updates; R11–15 genuinely retrain remaining clients from each corrected branch checkpoint. Selected membership is fixed using only R1–10. Remaining attackers keep their original schedule. No future historical local updates reused.',
    'matched_reference':'For each selected joint set, train an additional same-W9, same-participation branch with all remaining snapshots unmodified from R10 onward. This privileges clean snapshots and does not remove contamination already in W9. Separately report distance to the paired all-client clean history, whose participation differs.',
    'metrics':'Full/component ASR, clean accuracy/macro-F1, original mass removed, parameter distance and prediction disagreements; direct joint-minus-best-individual reduction and descriptive benign-control ranks. No interaction/intent theorem or p-value.',
    'fixed_test_scope':'Selected/individual/two continuation-control/no-intervention R10 and R15 endpoints on the existing test fold; it was used in prior studies and is not a pristine external holdout.',
    'code_sha256':{n:sha256_file(OUT/n) for n in ('group_common.py','select_groups.py')},
    'fresh_TPM_attestation':False,'ToN_IoT_included':False,'production_code_changed':False,'thesis_changed':False}
save(LAB/'protocol-before-selection.json',protocol)
# Authenticate each selected source manifest against a pre-existing closure.
pins={}
for role,cohorts in [('fit',fit),('calibration',cal)]:
    for cohort,paths in cohorts.items():
        for relative in paths:
            w=REPO/relative
            if relative.startswith('artifacts/revision-dba-three-seed-v1/'):
                expected=read(w.parent/'reports'/f'{w.name}.json')['creation']['manifest_sha256']
            else:
                closure=next(REPO/n for n in source_closures if w.is_relative_to((REPO/n).parent))
                expected=read(closure)['files'][w.relative_to(closure.parent).as_posix()+'/manifest.json']
            authenticate(w,expected);pins[relative]={'role':role,'cohort':cohort,'manifest_sha256':expected}
for task in tasks:
    w=SOURCE/'private-episodes'/task['stream'];expected=read(SOURCE/'study-artifact-closure.json')['files'][w.relative_to(SOURCE).as_posix()+'/manifest.json']
    authenticate(w,expected);pins[w.relative_to(REPO).as_posix()]={'role':'evaluation','cohort':task['cohort'],'manifest_sha256':expected,'task':task}
save(LAB/'private-source-pins.json',pins)
print('PROTOCOL AND SOURCE ANCHORS FROZEN',flush=True)
cfg=read(CFG);validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
public=[];private={}
for i,(relative,source) in enumerate(sorted(pins.items())):
    alias=f'case-{i:03d}';destination=LAB/'observable-inputs'/alias
    commitment=materialize_observable(REPO/relative,destination,deps,validation,envelope=source['role']=='evaluation')
    public.append({'alias':alias,'role':source['role'],'cohort':source['cohort'],**commitment})
    private[alias]={'source':relative,**source}
    print('OBSERVABLE PREFIX',alias,source['role'],source['cohort'],flush=True)
save(LAB/'observable-index.json',{'cases':public,'horizon':10,'private_rows_or_attack_labels_exported':False})
save(LAB/'private-alias-map.json',private)
print('OBSERVABLE PREFIXES READY',len(public),flush=True)
