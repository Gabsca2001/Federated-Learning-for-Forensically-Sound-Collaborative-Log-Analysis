"""Read-only selected-prefix reconstruction and frozen-V4 error diagnosis.

Shadow profiles are common-parent controls, not newly trained trajectories.
Unpoisoned client rows are controller-only oracle information in this study.
"""
from pathlib import Path
import os
import argparse,json,os
import numpy as np
import revision_attribution_recovery as source
from retrospective_anomaly_groups import detect
from selector_diagnostic_math import decompose,class_effect,confusion_metrics
from endpoint_attack_selection import poisoned_endpoint
from endpoint_recovery_protocol import forged_delta
from coherent_dba_selection import poison_commitment
from coherent_gradient_protocol import update_record,assess_round,verify_round,delta_digest
from revision_study_data import read,Generator
from revision_dba_experiment import save,evaluate,model_with_arrays,authenticate
from fl_forensics.byzantine import update_indicators
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.canonical import sha256_file

R=source.R;P=source.D;S=P/'source-evidence'
D=R/'results/admission/revision-selector-diagnosis-v1'
O=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'selector-diagnosis-20261107')

def guard():
    fs=os.statvfs('/mnt/c');free=fs.f_bavail*fs.f_frsize
    used=source.prior.source.allocated(D)+source.prior.source.allocated(O/'published')
    if free<8*1024**3 or used>32*1024**2:raise RuntimeError('Fixed diagnosis storage budget/floor failed')
    return dict(host_free_bytes=free,new_allocated_bytes=used)

def locks():
    paths=[R/'scripts'/n for n in ('revision_selector_diagnosis.py','selector_diagnostic_math.py')]
    paths+=[R/'tests/test_selector_diagnostic_math.py']
    return {str(p.relative_to(R)):sha256_file(p) for p in paths}

def check(p):
    assert locks()==p['source_locks'];original=read(P/'protocol-before-training.json');source.check(original)
    assert sha256_file(P/'protocol-before-training.json')==p['source_protocol_sha256']
    assert sha256_file(P/'file-checksums.json')==p['source_publication_index_sha256']
    assert all(sha256_file(P/n)==h for n,h in read(P/'file-checksums.json').items())
    assert sha256_file(S/'reference.json')==p['reference_sha256'] and sha256_file(S/'calibration.json')==p['calibration_sha256']
    return original

def prepare():
    assert not D.exists();storage=guard();original=read(P/'protocol-before-training.json');source.check(original)
    p=dict(profile='frozen-v4-diagnostic-decomposition-v1',source_locks=locks(),
        source_protocol_sha256=sha256_file(P/'protocol-before-training.json'),
        source_publication_index_sha256=sha256_file(P/'file-checksums.json'),
        reference_sha256=sha256_file(S/'reference.json'),calibration_sha256=sha256_file(S/'calibration.json'),
        cases=original['tasks'],window=list(range(1,11)),
        reconstruction='All ten original source histories, selected R1-10 submissions/checkpoints only. Recompute honest gradients and selected nonzero poisoned endpoints at actual parents. Alpha0 endpoints need not be trained because the submitted vector is exactly honest regardless of that unobserved endpoint. Compare complete round events, all input digests and checkpoint digests. Unselected adaptive queries and R11-15 are not rerun.',
        profiles=['actual','all_honest_same_parent','matched_clean_parent'],
        controls='At every actual source parent, replace all adversarial vectors by fresh honest gradients but keep the parent fixed. For benign clients this preserves their vectors and validation impact exactly, changing only peer-relative statistics. Compare that hypothetical profile to actual clean-prefix observations from the same allocation at the same round. Shadow windows follow the original parent sequence; they are not a new all-honest training trajectory.',
        channels='Expose raw norm, peer median norm, validation impact, each standardized channel, maximum score, strict exceedance, median fifth/sixth order statistics and active intervals. Reproduce frozen decisions; never refit, retune or authorize exclusions.',
        false_positive_audit='For every benign identity flagged by original V4, inspect all ten rounds. Compare paired confusion matrices and per-class F1, local common training loss before/after the honest exported update, and float64 common weighted validation loss. Labels and original error membership are evaluation-only; no detector sees them.',
        hypothesis='Test whether benign flags arise from the current parent state, peer normalization, the discontinuous macro-F1 validation impact, or mixed channels. Diagnose intermittent misses and oversized cliques using retained per-round evidence, without choosing a replacement threshold from these labels.',
        oracle_scope='The simulator accesses original unpoisoned client data to construct common-parent honest controls and local losses. This is not operational server access, independent data or a deployable detector.',
        invariants='Original classifier core, V4 rule, thresholds, original evidence, defaults and thesis stay unchanged. No new attack campaign, test inference, TPM Quote or client signature.',
        maximum_combined_output_bytes=32*1024**2,minimum_host_free_bytes=8*1024**3,storage_before=storage)
    D.mkdir();save(D/'protocol-before-diagnosis.json',p)
    print(json.dumps(dict(prepared=True,cases=len(p['cases']),selected_prefix_rounds=100,storage=storage)),flush=True)

class Engine(source.Engine):
    def __init__(self,p):
        self.diagnostic_protocol=p;super().__init__(check(p),write=False)
        self.reference=read(S/'reference.json');self.calibration=read(S/'calibration.json')
        self.metric_cache={};self.validation_loss_cache={};self.poison_endpoint_fits=0;self.skipped_alpha0_fits=0

    def sha(self,model):return source.prior.source.pilot.old_study.export_digest(model)

    def clean_metric(self,model):
        key=self.sha(model)
        if key not in self.metric_cache:
            v=evaluate(model,self.evaluation,self.deps)
            self.metric_cache[key]={k:v[k] for k in ('accuracy','macro_f1_all_model_classes','confusion_matrix')}
            cm=confusion_metrics(v['confusion_matrix']['values'])
            assert abs(cm['macro_f1']-v['macro_f1_all_model_classes'])<1e-12
        return self.metric_cache[key]

    def validation_loss(self,model):
        key=self.sha(model)
        if key not in self.validation_loss_cache:
            self.validation_loss_cache[key]=source.prior.source.pilot.gradient_step(model,self.evaluation,self.weights,self.deps)[1]
        return self.validation_loss_cache[key]

    def observe(self,parent,updates,number):
        clients=sorted(updates);deltas=[updates[c]['delta'] for c in clients]
        indicators=update_indicators(deltas,client_ids=clients);base=arrays_from_export(parent,np=np)
        base_f1=self.clean_metric(parent)['macro_f1_all_model_classes']
        for c,item in zip(clients,indicators,strict=True):
            local=model_with_arrays(parent,[a+d for a,d in zip(base,updates[c]['delta'],strict=True)])
            item['validation_impact']=base_f1-self.clean_metric(local)['macro_f1_all_model_classes']
        return dict(round_number=number,client_ids=clients,deltas=deltas,indicators=indicators)

    def prefix(self,task):
        history=read(S/'histories'/task['alias']/'result.json');rows=self.training_rows(task['seed']);clients=sorted(rows)
        plan=source.prior.source.plan_for(task);parent=self.initial
        actual=[];shadow=[];parents=[];honest_by_round=[];local_losses=[];traces=[]
        for record in history['journal'][:10]:
            guard();number=record['round'];context=record['event']['context'];base=arrays_from_export(parent,np=np)
            assert self.sha(parent)==context['parent_model_sha256']
            if number>1:assert self.clean_metric(parent)==history['journal'][number-2]['metrics']['clean']
            honest={};losses={}
            for c in clients:honest[c],losses[c]=source.prior.source.pilot.gradient_step(parent,rows[c],self.weights,self.deps)
            updates={};poisoning={};alpha=record['selected_alpha'];active=task['mode']!='clean'
            for c in clients:
                delta=honest[c]
                if active and c in task['attackers']:
                    changed,poison=source.prior.source.poison_local_rows(rows=rows[c],plan=plan,client_id=c,round_number=number,distributed=task['mode']!='complete-trigger')
                    poisoning[c]=poison_commitment(poison)
                    if alpha:
                        endpoint=poisoned_endpoint(parent,changed,self.weights,task['seed']+number*10000+int(c[6:])-1,self.deps)
                        poisoned=[a.astype(float)-b for a,b in zip(arrays_from_export(endpoint,np=np),base,strict=True)]
                        delta,_=forged_delta(honest[c],poisoned,alpha,task['family']);self.poison_endpoint_fits+=1
                    else:self.skipped_alpha0_fits+=1
                updates[c]=update_record(c,context,delta,len(rows[c]),True)
            assert poisoning==record['poisoning']
            params,event=assess_round(base,updates,None,context);assert event==record['event']
            verify_round(base,updates,None,context,event);candidate=model_with_arrays(parent,params)
            assert self.sha(candidate)==record['model_sha256']
            frame=self.observe(parent,updates,number)
            honest_updates={c:update_record(c,context,honest[c],len(rows[c]),True) for c in clients}
            other=self.observe(parent,honest_updates,number) if active else frame
            truth=set(task['attackers']) if active else set()
            for i,c in enumerate(clients):
                if c not in truth:
                    assert delta_digest(frame['deltas'][i])==delta_digest(other['deltas'][i])
                    assert frame['indicators'][i]['validation_impact']==other['indicators'][i]['validation_impact']
            actual.append(frame);shadow.append(other);parents.append(parent);honest_by_round.append(honest);local_losses.append(losses)
            traces.append(dict(round=number,parent_sha256=self.sha(parent),checkpoint_sha256=self.sha(candidate),
                input_delta_digests=event['input_delta_digests'],selected_alpha=alpha))
            parent=candidate
        expected=read(S/'selection'/f"{task['alias']}.json")
        assert detect(actual,self.reference,self.calibration)==expected
        return dict(actual=actual,shadow=shadow,parents=parents,honest=honest_by_round,losses=local_losses,traces=traces,
            source_result=history,selection=expected)

    def diagnosis(self,task,matched_clean,rebuilt):
        truth=set(task['attackers']) if task['mode']!='clean' else set();expected=rebuilt['selection']
        false_clients=sorted(set(expected['individual_anomalies'])-truth)
        profiles={};decisions={}
        for name,frames in [('actual',rebuilt['actual']),('all_honest_same_parent',rebuilt['shadow']),('matched_clean_parent',matched_clean['actual'])]:
            profiles[name]=decompose(frames,self.reference,self.calibration)
            decisions[name]=detect(frames,self.reference,self.calibration)
            for record in profiles[name]['rows']:
                r=rebuilt['source_result']['journal'][record['round']-1]
                proof=r['relative_radius_proofs'].get(record['client'])
                record['scheduled_adversary_for_evaluation_only']=record['client'] in truth
                record['actually_modified_in_source']=bool(proof and proof['perturbation_norm']>0)
            for record in profiles[name]['clients']:
                c=record['client'];record['scheduled_adversary_for_evaluation_only']=c in truth
                record['source_modified_rounds']=[r['round'] for r in rebuilt['source_result']['journal'][:10]
                    if r['relative_radius_proofs'].get(c,{}).get('perturbation_norm',0)>0]
        fp=[]
        raw={(r['client'],r['round']):r for r in profiles['actual']['rows']}
        for c in false_clients:
            for number in range(1,11):
                parent=rebuilt['parents'][number-1];base=arrays_from_export(parent,np=np)
                delta=rebuilt['honest'][number-1][c]
                local=model_with_arrays(parent,[a+d for a,d in zip(base,delta,strict=True)])
                before=self.clean_metric(parent);after=self.clean_metric(local)
                changes=class_effect(before['confusion_matrix']['values'],after['confusion_matrix']['values'])
                assert abs(changes['macro_f1_change']+raw[(c,number)]['validation_impact'])<1e-12
                local_after=source.prior.source.pilot.gradient_step(local,self.training_rows(task['seed'])[c],self.weights,self.deps)[1]
                loss_before=rebuilt['losses'][number-1][c]
                val_before=self.validation_loss(parent);val_after=self.validation_loss(local)
                fp.append(dict(client=c,round=number,score=raw[(c,number)]['score'],active=raw[(c,number)]['active'],
                    dominant_channel=raw[(c,number)]['dominant_channel'],parent_clean_f1=before['macro_f1_all_model_classes'],
                    endpoint_clean_f1=after['macro_f1_all_model_classes'],class_names=self.initial['class_names'],**changes,
                    local_training_loss_before=loss_before,local_training_loss_after=local_after,local_training_loss_change=local_after-loss_before,
                    validation_common_loss_before=val_before,validation_common_loss_after=val_after,validation_common_loss_change=val_after-val_before,
                    parent_confusion=before['confusion_matrix']['values'],endpoint_confusion=after['confusion_matrix']['values']))
        return dict(task=task,profiles=profiles,decisions=decisions,false_positive_details=fp,
            selected_prefix_trace=rebuilt['traces'],false_clients=false_clients,
            source_result_sha256=sha256_file(S/'histories'/task['alias']/'result.json'))

def run():
    p=read(D/'protocol-before-diagnosis.json');engine=Engine(p);E=D/'evidence';assert not E.exists();save(E/'protocol.json',p)
    clean={};index=[]
    for task in p['cases']:
        if task['mode']=='clean':clean[task['seed']]=engine.prefix(task)
    for task in p['cases']:
        rebuilt=clean[task['seed']] if task['mode']=='clean' else engine.prefix(task)
        result=engine.diagnosis(task,clean[task['seed']],rebuilt)
        save(E/'cases'/f"{task['alias']}.json",result)
        index.append(dict(alias=task['alias'],source_selected_group=result['decisions']['actual']['selected_group'],
            same_parent_honest_group=result['decisions']['all_honest_same_parent']['selected_group'],
            same_parent_honest_anomalies=result['decisions']['all_honest_same_parent']['individual_anomalies'],
            false_clients=result['false_clients']))
        print(json.dumps(index[-1]),flush=True)
    save(E/'case-index.json',dict(cases=index,selected_prefix_rounds=100,conditional_honest_parent_contexts=80,
        poisoned_endpoint_fits=engine.poison_endpoint_fits,unobservable_alpha0_endpoint_fits_skipped=engine.skipped_alpha0_fits,
        all_source_decisions_reproduced=True,original_thresholds_unchanged=True))
    check(p);Generator.close(E);save(D/'closure.json',dict(manifest_sha256=sha256_file(E/'manifest.json'),storage=guard()))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=('prepare','run'));args=parser.parse_args()
    {'prepare':prepare,'run':run}[args.phase]()
