"""Retrospective mass-guard audit of frozen histories, not a new defense trial."""
from __future__ import annotations
import csv
import json
from collections import Counter,defaultdict
from fractions import Fraction
from pathlib import Path
import os
import shutil
import admission_mass_safety as guard
import revision_severe_gate_study as study
from revision_study_data import read
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export

ROOT=study.ROOT;SOURCE=study.LAB;LAB=ROOT/'artifacts/revision-admission-mass-safety-v1'
LOCAL=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'mass-safety-mail-audit-20261106')
POLICIES={'retention_only_control':guard.MassSafetyPolicy(maximum_group_share=Fraction(1)),
          'retention_and_group_cap':guard.MassSafetyPolicy()}


def write_csv(path,rows):
    with path.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(dict.fromkeys(k for r in rows for k in r)))
        writer.writeheader();writer.writerows(rows)


def main():
    assert not LAB.exists(),'Preserve prior audit'
    protocol=read(SOURCE/'evaluation/protocol-before-training.json');study.assert_locks(protocol)
    publication=read(ROOT/'results/revision-severe-tail-gate-v1/publication-verification.json')
    assert publication['status']=='verified'
    assert publication['summary_sha256']==sha256_file(ROOT/'results/revision-severe-tail-gate-v1/summary.json')
    LAB.mkdir()
    locks={str(p.relative_to(ROOT)):sha256_file(p) for p in (
        ROOT/'scripts/admission_mass_safety.py',Path(__file__),ROOT/'tests/test_admission_mass_safety.py')}
    plan=dict(profile='retrospective-fedavg-mass-safety-audit-v1',posthoc=True,
        source_verified_sha256=sha256_file(SOURCE/'evaluation/verified/summary.json'),
        source_publication_sha256=sha256_file(ROOT/'results/revision-severe-tail-gate-v1/publication-verification.json'),
        policies={k:p.record() for k,p in POLICIES.items()},source_locks=locks,
        threshold_rationale='The4/5 per-round mass floor is the existing severe-study guard. k=3 is the declared three-of-fifteen identity budget.1/3 is a declared conservative influence allocation, not a learned cutoff or a backdoor theorem. Both fixed policies are reported; none is selected by attack outcomes.',
        inference='All source outcomes were already observed. This is a retrospective mechanism/availability audit, not held-out security validation. Later source checkpoints after a deferral are not defended continuations.',
        numerical_scope='For the joint guard, first/last locally authorized source rounds per case repeat actual Flower aggregation with authenticated originals. No training, timestamp request or TPM Quote is created.',
        new_TPM_quotes=0,new_training=0,new_profile_ASR=None)
    save(LAB/'protocol-before-audit.json',plan)
    audit=read(SOURCE/'evaluation/verified/summary.json');assert audit['status']=='verified' and len(audit['cases'])==96
    assessments=[];cases=[];backend_checks=[];rejected_callback_checks=0
    study.configure('evaluation')
    for c in audit['cases']:
        task=c['task'];source=SOURCE/'evaluation/cases'/task['name']/'evidence'
        assert sha256_file(source/'manifest.json')==c['source_manifest_sha256']
        entries=read(source/'manifest.json')['core']['artifacts']
        def authenticated(relative):
            path=source/relative;assert sha256_file(path)==entries[relative];return read(path)
        locally_ready=[]
        for name,policy in POLICIES.items():
            reports=[]
            for row in c['rows']:
                inputs=dict(nominal_counts=row['example_counts'],effective_masses=row['masses'],
                    mandatory_gates={i:True for i in row['statuses']},statuses=row['statuses'],policy=policy)
                report=guard.assess_mass_safety(**inputs);assert guard.verify_mass_safety(report,**inputs)==report['aggregation_authorized']
                if not report['aggregation_authorized']:
                    def forbidden_backend(_):raise AssertionError('Deferred round invoked numerical backend')
                    output,again=guard.guarded_aggregation(forbidden_backend,**inputs)
                    assert output is None and again==report;rejected_callback_checks+=1
                elif name=='retention_and_group_cap':locally_ready.append((row,inputs,report))
                reports.append(report)
                assessments.append(dict(case=task['name'],cohort=task['cohort'],seed=task['seed'],method=task['method'],
                    mode=task['mode'],guard=name,round=row['round'],decision=report['decision'],
                    reasons='|'.join(report['reasons']),retained_mass=report['retained_mass_fraction'],
                    maximum_at_most_k_share=report['maximum_at_most_k_share'],
                    assessment_sha256=report['assessment_sha256'],inputs=inputs if False else None))
            deferred=[i+1 for i,r in enumerate(reports) if not r['aggregation_authorized']]
            cases.append(dict(case=task['name'],cohort=task['cohort'],seed=task['seed'],method=task['method'],mode=task['mode'],
                guard=name,source_complete=c['complete'],source_rounds=len(reports),
                first_deferred_round=min(deferred,default=None),locally_deferred_rounds=len(deferred),
                uninterrupted_source_prefix_compatible=not deferred and c['complete'],
                new_defended_endpoint_ASR=None))
        if locally_ready:
            gen,_,_=study.context(protocol,task);settings=study.base.settings_for(protocol)
            chosen={items[0]['round']:items for items in (locally_ready[0],locally_ready[-1])}
            for number,(row,inputs,expected) in chosen.items():
                prefix=f'rounds/round-{number:03d}'
                initial=authenticated(prefix+'/base-model.json');state=authenticated(prefix+'/gate-state.json')
                exports=[authenticated(prefix+f'/updates/{i}.json') for i in gen.clients]
                arrays=[arrays_from_export(e,np=study.base.np) for e in exports]
                calls=[]
                def numerical_backend(weights):
                    model,_,coefficients=study.base.numerical(initial,arrays,gen,state,settings,task['policy'])
                    assert coefficients=={i:str(v) for i,v in weights.items()}
                    assert model==authenticated(prefix+'/global-model.json');calls.append(True)
                    return model
                output,actual=guard.guarded_aggregation(numerical_backend,**inputs)
                assert output is not None and calls==[True] and actual==expected
                backend_checks.append(dict(case=task['name'],round=number,model_sha256=study.base.digest(output),
                    assessment_sha256=expected['assessment_sha256']))
        print(json.dumps(dict(audited=task['name'],source_rounds=len(c['rows']))),flush=True)
    assert len(assessments)==2*1412 and len(cases)==2*96
    grouped=defaultdict(list)
    for c in cases:grouped[(c['cohort'],c['method'],c['mode'],c['guard'])].append(c)
    aggregate=[]
    for (cohort,method,mode,name),cs in sorted(grouped.items()):
        relevant=[r for r in assessments if r['cohort']==cohort and r['method']==method and r['mode']==mode and r['guard']==name]
        counts=Counter(reason for r in relevant for reason in r['reasons'].split('|') if reason)
        aggregate.append(dict(cohort=cohort,method=method,mode=mode,guard=name,source_cases=len(cs),
            source_rounds=len(relevant),locally_deferred_rounds=sum(r['decision']=='defer' for r in relevant),
            uninterrupted_compatible_cases=sum(c['uninterrupted_source_prefix_compatible'] for c in cs),**counts))
    for path,digest in locks.items():assert sha256_file(ROOT/path)==digest
    study.assert_locks(protocol)
    write_csv(LAB/'rounds.csv',assessments);write_csv(LAB/'cases.csv',cases);write_csv(LAB/'aggregate.csv',aggregate)
    save(LAB/'backend-checks.json',dict(checks=backend_checks,rejected_callbacks_not_invoked=rejected_callback_checks))
    summary=dict(status='verified',profile=plan['profile'],posthoc=True,source_cases=96,source_rounds=1412,
        assessments=len(assessments),case_guard_pairs=len(cases),backend_checks=len(backend_checks),
        rejected_callbacks_not_invoked=rejected_callback_checks,new_training=0,new_TPM_quotes=0,new_profile_ASR=None,
        automatic_production_promotion=False,thesis_edited=False,aggregate=aggregate,
        source_verified_sha256=plan['source_verified_sha256'],protocol_sha256=sha256_file(LAB/'protocol-before-audit.json'))
    save(LAB/'summary.json',summary)
    save(LAB/'inventory.json',dict(files={p.name:sha256_file(p) for p in LAB.iterdir() if p.is_file()}))
    for path in LAB.iterdir():
        if path.is_file():shutil.copy2(path,LOCAL/('mass-safety-'+path.name))
    print(json.dumps({k:v for k,v in summary.items() if k!='aggregate'},indent=2))


if __name__=='__main__':main()
