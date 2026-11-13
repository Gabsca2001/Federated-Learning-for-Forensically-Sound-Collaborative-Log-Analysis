"""Create a separate auditable V5 controller from the verified recovery engine."""
from pathlib import Path
import shutil
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis');O=Path(__file__).parent
text=(R/'scripts/revision_attribution_recovery.py').read_text()
def once(a,b):
    global text
    assert text.count(a)==1,(a,text.count(a));text=text.replace(a,b)
once('Frozen V4 attribution assessment and fresh-parent recovery from pre-attack W0.',
     'Frozen V5 episode attribution, matched V4 comparison and origin recovery.')
once('from pathlib import Path\nimport argparse,os,json\nimport numpy as np',
     "import os\nfor name in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):os.environ[name]='1'\nfrom pathlib import Path\nimport argparse,json\nimport numpy as np")
once('import revision_endpoint_groups_v2 as prior','import revision_endpoint_groups_v2 as prior\nimport revision_selector_diagnosis as diagnosis')
once('from retrospective_anomaly_groups import fit_reference,calibrate,detect','from episodic_attribution_groups import fit_reference,calibrate,detect')
once('from fl_forensics.canonical import sha256_file','from fl_forensics.canonical import sha256_file\nfrom fl_forensics.distributed_backdoor import DistributedBackdoorPlan')
once('results/revision-attribution-origin-recovery-v1','results/revision-episodic-attribution-recovery-v1')
once('output/attribution-recovery-20261107','output/episode-attribution-20261107')
once("ASSIGN={6122001:['client02','client08','client15'],6123001:['client03','client07','client11']}",
     "ASSIGN={6124001:['client01','client09','client14'],6125001:['client04','client08','client12']}")
once("names=['revision_attribution_recovery.py','retrospective_anomaly_groups.py','endpoint_recovery_protocol.py']",
     "names=['revision_episode_attribution.py','episodic_attribution_groups.py','retrospective_anomaly_groups.py','endpoint_recovery_protocol.py']")
once("R/'tests/test_retrospective_anomaly_groups.py'","R/'tests/test_episodic_attribution_groups.py'")
once('    return previous\n',"    dp=read(diagnosis.D/'protocol-before-diagnosis.json');diagnosis.check(dp)\n    assert sha256_file(diagnosis.D/'file-checksums.json')==p['diagnosis_publication_index_sha256']\n    assert all(sha256_file(diagnosis.D/n)==h for n,h in read(diagnosis.D/'file-checksums.json').items())\n    return previous\n")
once('    require_unique_allocations(allocations)',
     "    old_assessment=read(diagnosis.P/'protocol-before-training.json')\n    for seed in (6122001,6123001):allocations[str(seed)]=old_assessment['allocation_preflight'][str(seed)]\n    require_unique_allocations(allocations)")
start=text.index('    tasks=[]\n');end=text.index('    p=dict(',start)
text=text[:start]+'''    tasks=[]
    for seed,attackers in ASSIGN.items():
        tasks.append(dict(alias=f'case-{len(tasks):02d}',seed=seed,attackers=attackers,mode='clean',family='unrestricted',role='assessment',schedule='persistent',attack_rounds=list(range(1,11))))
        for family in ('unrestricted','relative-radius'):
            for mode in ('distributed','complete-trigger'):
                tasks.append(dict(alias=f'case-{len(tasks):02d}',seed=seed,attackers=attackers,mode=mode,family=family,role='assessment',schedule='persistent',attack_rounds=list(range(1,11))))
        for mode in ('distributed','complete-trigger'):
            tasks.append(dict(alias=f'case-{len(tasks):02d}',seed=seed,attackers=attackers,mode=mode,family='unrestricted',role='assessment',schedule='intermittent',attack_rounds=[1,2,4,7,10]))
'''+text[end:]
once("profile='attribution-origin-recovery-v1'","profile='separated-episodic-attribution-origin-recovery-v1'")
once("prior_publication_index_sha256=sha256_file(prior.D/'file-checksums.json'),",
     "prior_publication_index_sha256=sha256_file(prior.D/'file-checksums.json'),diagnosis_publication_index_sha256=sha256_file(diagnosis.D/'file-checksums.json'),")
once("selector='V4: pooled clean log1p(relative norm) and positive validation-impact standardized increases; median of ten per-round maximum channel scores gives individual persistence. Fit2/calibrate3 clean campaigns; strict campaign-max threshold. Anomalous-client pairs require coactivity fraction strictly above max(.3,all clean calibration pair fractions). Maximal cliques, largest feasible then weakest persistent score then lexical order. Tensor pair descriptors are separate evidence. No known group size, labels, ASR or future rounds select groups.'",
     "selector='V5 separates macro-F1 utility risk from identity evidence. Identity statistic is the THIRD-largest clean-standardized log1p(relative norm) in R1-10. Calibrate its threshold by maximum clean campaign/client statistic. Group edges require both individual episode flags and coexceedance in more than max(2,all clean pair coexceedance counts) rounds on this SAME norm mechanism. Maximal cliques ranked by size then weakest episode score, leaving10 clients. No known attacker count or outcome enters selection. Tensor descriptors remain separate. Utility median and original V4 rule are recalibrated on the SAME five clean inputs and reported without creating V5 identity/group flags.'")
once("calibration='Reuse five clean-only allocation roles from the failed V2/V3 transfer, freshly reconstruct their observations. New rule is developed after that failure; assessment uses two actual new allocations and attacker rosters frozen before new outcomes. Same reused Data24 population, initial model and validation, not independent-data confirmation.'",
     "calibration='Reuse five clean development allocation roles, freshly reconstructed. Fit2/calibrate3; V5 episode/coactivity and V4 comparison calibration share the same clean observations. Freeze new two-allocation assessment and different attacker identities before outcomes; check all11 memberships distinct. Rule development follows the published V4 diagnosis. Same reused Data24 population/W0/validation, not independent-data confirmation.'")
once("training='Same full-batch float64 eval-mode coherent honest gradient, eta.001 and globally normalized weighted loss. Raw count-weighted FedAvg, minimum10 contributors; all prerequisite trust gates assumed passed in software.'",
     "training='Same full-batch float64 eval-mode coherent honest gradient,eta.001,globally normalized weighted loss,raw count-weighted FedAvg,minimum10 contributors. All trust facts assumed passed in software. NumPy BLAS,MKL,OpenMP and PyTorch use1 thread fixed before numerical imports; no operator/hyperparameter tuning.'")
once("attacks='Three fixed identities,ceil(.5*n_i) hashed poisoned rows each,features13/17/24 set12,target benign,rounds1-10,unmodified continuation11-15. Distributed assigns one feature each; complete-trigger assigns all3. Same row budgets, different feature-edit budgets. Malicious endpoints use10 Adam epochs, batch128,lr.001 at every actual parent.'",
     "attacks='Three fixed identities,ceil(.5*n_i) hashed poisoned rows per active round,features13/17/24=12,target benign. Persistent scheduleR1-10; intermittent schedule[1,2,4,7,10]. Honest gradient in all inactive rounds,includingR11-15. Distributed assigns one feature each,complete-trigger all3. Match row budgets within a schedule; feature-edit budgets and total row-round budgets differ across variants/schedules. Malicious endpoints use10 Adam epochs,batch128,lr.001 at each actual active parent.'")
once("recovery='Selection closes before labels/effects. Full-origin replays for effective source attacks and clean false-group cases only. Start from the preserved pre-attack W0 and retrain ALL15 rounds after each group/individual omission. Remaining attackers retrain poisoned endpoints and rerun the same six adaptive queries at every corrected parent duringR1-10. No stale original updates or original alphas are replayed.'",
     "recovery='Selection closes before labels/effects. For effective raw attacks and clean false-group cases,retrain all15 rounds from preserved pre-attackW0 for each omission. Surviving attackers retrain endpoints and requery at their task-declared ACTIVE rounds,not necessarily allR1-10. Compare to a canonical same-excluded-roster clean reference independent of attack family/schedule. No stale historical vector or alpha is reused.'")
once('Maximum48 requested replay branches','Maximum80 requested replay branches')
once("interpretation='V4 flags concurrent abnormal updates, not proven collusion or permanent exclusion. Exact matching to same-roster clean counterfactual is conditional on a clean W0, correct attribution and complete removal of active attackers, deterministic training/data and declared protocol. W0 authenticity does not itself establish cleanliness.'",
     "interpretation='V5 reports repeated magnitude episodes and common-mechanism temporal group hypotheses,not proven malicious intent or automatic exclusion. Utility risks remain visible separately. Fewer-than-three,staggered or norm-bounded episodes may escape. Exact recovery requires cleanW0,correct attribution,complete attacker removal and deterministic declared data/training. Earlier benign influence already inW0 remains.'")
once("scope='Exploratory numerical research. Two fresh allocations reuse7096 rows and3163 root-disjoint validation rows; no test inference or independent dataset. No TPM/client signatures, new defaults or thesis edits. Previous failed selectors/late recovery and containment results remain unchanged.'",
     "scope='Exploratory offline research: fourteen histories on two fresh actual allocations,7096 reused training rows,3163 reused root-disjoint validation rows. No test inference,independent dataset,new TPM/client signatures,default or thesis change. Source training remains rawFedAvg; retrospective V5 does not prevent the source attack. All previous failures remain preserved.'")
once('maximum_recovery_branches=48','maximum_recovery_branches=80')
once('all_nine_memberships_unique=True','all_eleven_memberships_unique=True')
once('class Engine(prior.Engine):', '''def plan_for_task(task):
    original=prior.source.plan_for(task).model_dump(mode='json')
    original['attack_rounds']=task.get('attack_rounds',list(range(1,11)))
    return DistributedBackdoorPlan.model_validate(original)

class Engine(prior.Engine):''')
assert text.count('prior.source.plan_for(task)')==3
# Keep the plan constructor's original call; replace only the two use sites.
text=text.replace('outcomes(model,self.evaluation,prior.source.plan_for(task),','outcomes(model,self.evaluation,plan_for_task(task),')
text=text.replace('plan=prior.source.plan_for(task)','plan=plan_for_task(task)')
once("clean_task={**task,'alias':f\"clean-s{task['seed']}-omit-{group_key(removed)}\",'mode':'clean','role':'clean-reference'}",
     "clean_task={**task,'alias':f\"clean-s{task['seed']}-omit-{group_key(removed)}\",'mode':'clean','role':'clean-reference','family':'unrestricted','schedule':'clean-reference','attack_rounds':list(range(1,11))}")
once("active=task['mode']!='clean' and number<=10", "active=task['mode']!='clean' and number in task.get('attack_rounds',list(range(1,11)))")
once("groups=[('v4',sorted(group))]","groups=[('v5',sorted(group))]")
once("maximum_recovery_branches'],'Explicit branch budget exceeded; no case trimming allowed'","maximum_recovery_branches'],'Explicit branch budget exceeded; no case trimming allowed'")
text=text.replace('self.v4','self.v5')
dest=R/'scripts/revision_episode_attribution.py';assert not dest.exists();dest.write_text(text);shutil.copy2(dest,O/dest.name)
for n,folder in [('episodic_attribution_groups.py','scripts'),('test_episodic_attribution_groups.py','tests')]:
    dest=R/folder/n;assert not dest.exists();shutil.copy2(O/n,dest)
print('Separate V5 controller installed; predecessor methods and numerical core unchanged.')
