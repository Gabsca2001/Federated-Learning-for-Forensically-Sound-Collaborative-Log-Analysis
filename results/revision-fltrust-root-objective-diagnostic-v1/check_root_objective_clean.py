"""Explicit post-hoc clean-only loss-weighting ablation, not attack retuning."""
from pathlib import Path
from collections import Counter
import json,hashlib,sys,os
import numpy as np
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis');O=Path(__file__).parent
D=R/'results/revision-fltrust-root-objective-diagnostic-v1';S=R/'results/revision-fltrust-screen-v1';A=R/'artifacts/revision-capped-final-v1'
sys.path.insert(0,str(R/'scripts'))
import revision_fltrust_screen as study
from fltrust_screen_aggregation import fltrust_delta
from revision_dba_experiment import evaluate,model_with_arrays
from fl_forensics.federated_model import dependencies,arrays_from_export
def read(p):return json.loads(p.read_bytes())
def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
def save(p,v):
    assert not p.exists(),p
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
def guard():
    s=os.statvfs('/mnt/c');free=s.f_bavail*s.f_frsize
    used=sum(f.stat().st_blocks*512 for folder in (S,D,O/'published',O/'root-objective-diagnostic') if folder.exists() for f in folder.rglob('*') if f.is_file())
    assert free>=8*1024**3 and used<64*1024**2
    return {'host_free_bytes':free,'combined_result_allocation_bytes':used}
def main():
    assert not D.exists(),'Preserve prior diagnostic';p=read(S/'protocol-before-root-training.json');old=study.check(p)
    assert read(S/'verification.json')['status']=='verified'
    selected=[e for e in p['cases'] if e['task']['mode']=='clean'];assert len(selected)==4
    # Fix all settings before training. Existing attacked rows are not read here.
    save(D/'protocol-before-clean-ablation.json',{'source_protocol_sha256':sha(S/'protocol-before-root-training.json'),
        'script_sha256':sha(Path(__file__)),'source_locks':p['source_locks'],
        'selection':'All four clean source histories, all originally selected rounds, all three original root draws. No new attacked rows or test predictions.',
        'change':'Only root Adam loss weights change to one for all six classes; same48 rows,10 epochs,batch128,lr.001,seeds and original client updates.',
        'reason':'Balanced root sampling plus inherited global class weights gives exfiltration31.8853% and multi_tactic5.0298% of nominal root loss weight, rather than16.6667% each.',
        'interpretation':'Post-hoc diagnostic after the first exploratory screen; no independent confirmation or unseen-data claim.',
        'continuation_rule':'Do not open new attack evaluation unless every clean context/draw retains at least ten positive-score contributors and loses at most2 percentage points F1 against both robust and capped same-input controls.',
        'storage_before':guard()})
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
    original=read(Path(old['training']['validation_path']))['rows']['validation'];byid={r['window_id']:r for r in original}
    pool=set(p['root_pool_ids']);evaluation=[r for r in original if r['window_id'] not in pool];records=[]
    for entry in selected:
        name=entry['task']['name'];case=read(S/'cases'/f'{name}.json')
        for row in case['rows']:
            guard();folder=A/'cases'/name/'evidence/rounds'/f"round-{row['round']:03d}"
            initial=read(folder/'base-model.json');base=arrays_from_export(initial,np=np)
            clients=sorted(stem.stem for stem in (folder/'updates').glob('*.json'))
            raw={c:[a.astype(float)-b for a,b in zip(arrays_from_export(read(folder/'updates'/f'{c}.json'),np=np),base,strict=True)] for c in clients}
            for seed in p['root_seeds']:
                root_rows=[byid[i] for i in p['root_draws'][str(seed)]]
                root_model,indices=study.root_update(initial,root_rows,'adam10',seed,deps,{c:1. for c in initial['class_names']})
                again,again_indices=study.root_update(initial,root_rows,'adam10',seed,deps,{c:1. for c in initial['class_names']})
                assert root_model==again and indices==again_indices
                rd=[a.astype(float)-b for a,b in zip(arrays_from_export(root_model,np=np),base,strict=True)]
                delta,d=fltrust_delta(raw,rd,{c:True for c in clients})
                model=model_with_arrays(initial,[b+a for b,a in zip(base,delta,strict=True)])
                clean=evaluate(model,evaluation,deps)
                cm=clean['confusion_matrix']['values'];f1=[]
                for i in range(len(cm)):
                    den=sum(cm[i])+sum(cm[j][i] for j in range(len(cm)));f1.append(2*cm[i][i]/den if den else 0.)
                assert abs(sum(f1)/len(f1)-clean['macro_f1_all_model_classes'])<1e-12
                previous=next(ref for ref in row['references'] if ref['root_method']=='adam10' and ref['root_seed']==seed)
                losses={c:row['baselines'][c]['validation']['clean']['macro_f1_all_model_classes']-clean['macro_f1_all_model_classes'] for c in ('robust','capped')}
                records.append({'case':name,'round':row['round'],'root_seed':seed,'positive_contributors':d['positive_contributors'],
                     'root_model_sha256':study.export_digest(root_model),'fltrust_model_sha256':study.export_digest(model),
                     'root_delta_norm':d['root_norm'],'derivation':d,'clean_macro_f1':clean['macro_f1_all_model_classes'],
                     'clean_confusion_matrix':clean['confusion_matrix'],
                     'weighted_reference_clean_macro_f1':previous['fltrust']['validation']['clean']['macro_f1_all_model_classes'],
                     'clean_f1_losses':losses,'root_only_clean_macro_f1':evaluate(root_model,evaluation,deps)['macro_f1_all_model_classes']})
            print(json.dumps({'clean_case':name,'round':row['round'],'root_draws_completed':len(records)}),flush=True)
    summary={'scope':'Post-hoc clean-only objective diagnosis; no new attack inference or client training.',
       'contexts':16,'root_configurations':len(records),'root_training_replays':len(records),
       'below_positive_quorum10':sum(r['positive_contributors']<10 for r in records),
       'unweighted_f1_higher_than_weighted':sum(r['clean_macro_f1']>r['weighted_reference_clean_macro_f1']+1e-12 for r in records),
       'unweighted_f1_lower_than_weighted':sum(r['clean_macro_f1']<r['weighted_reference_clean_macro_f1']-1e-12 for r in records),
       'comparisons':{c:{'losses_over_two_points':sum(r['clean_f1_losses'][c]>.02 for r in records),
          'worst_loss_points':100*max(r['clean_f1_losses'][c] for r in records)} for c in ('robust','capped')},
       'all_clean_continuation_guards_pass':all(r['positive_contributors']>=10 and max(r['clean_f1_losses'].values())<=.02 for r in records),
       'storage_after':guard(),'new_attack_evaluation_performed':False,'test_inference':False}
    save(D/'records.json',records);save(D/'summary.json',summary);study.check(p)
    print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
