"""All named baselines on identical native-gradient source observations."""
from pathlib import Path
import json
import sys
import time

import numpy as np
import yaml

OUT=Path(__file__).parent;sys.path[:0]=[str(OUT),str(OUT.parent/'state-conditioned-detector-20261103')]
from gradient_study import operation,read
from study_data import Generator
from revision_dba_experiment import save,outcomes,predict,evaluate,model_with_arrays,authenticate
from fl_forensics.byzantine import model_delta,update_indicators
from fl_forensics.canonical import sha256_file,sha256_bytes
from fl_forensics.composite_admission import build_indicator_references,score_statistical_indicators,calibrate_policy_thresholds,decide_admission_policies
from fl_forensics.composite_admission_models import TrustSignal
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.literature_baselines import flame_aggregate,weidetect_aggregate
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.round_derivation import implementation_sha256

REPO=Path.cwd();ROOT=REPO/'artifacts/revision-research-closure-v1';SOURCE=ROOT/'native-gradients-evaluation'
DEST=ROOT/'shared-gradient-replay';assert not DEST.exists()
cfg=read(REPO/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
cases=read(SOURCE/'results.json')['cases']
sources=[c for c in cases if c['task']['method']=='gradient_fedavg']
composite=yaml.safe_load(Path(cfg['composite_config_path']).read_text())
save(DEST/'protocol-before-comparison.json',{
    'profile':'shared-native-gradient-literature-comparison-v1','source':implementation_sha256(),
    'controller_sha256':sha256_file(Path(__file__)),'source_cases':[c['task'] for c in sources],
    'methods':['gradient_fedavg','literal_eq2','literal_eq3','normalized_eq2_adaptation','flame','weidetect','gated_composite'],
    'scope':'Secondary common-input analysis of frozen gradient-FedAvg histories, not new defense-controlled trajectories. Native methods receive the same actual/forged gradients and source history. Model aggregators receive the exact float64 one-step vectors B-eta*g, with final checkpoint dtype export. No Adam delta is represented as an honest derivative.',
    'attack':'Same saved selected gradient-forgery candidate for every method. This is transfer from the FedAvg-aware source attack, not a new query search against each comparator.',
    'calibration':'Per-round clean native-gradient reference only for composite, existing formula/margins unchanged. Initial correctly predicted confidence>=.90 auxiliary rows for WeiDetect; K12. FLAME noise .01. Different information budgets remain explicit.',
    'trust':'Software admissibility assumption G=1 for these frozen inputs; not a demonstrated bypass of attested execution or fresh TPM Quotes.',
    'test_access':False,'missing_or_invalid_outputs':'Explicit no-model/error, no imputed ASR.'})
(DEST/'controller.py').write_bytes(Path(__file__).read_bytes())
totals={'contexts':0,'outputs':0,'failed_outputs':0,'repeated_aggregations':0};records=[];refs={}

def gradients(prefix,gen,task,frame):
    base=read(prefix/'base-model.json');arrays=arrays_from_export(base,np=np)
    with np.load(prefix/'gradient-endpoints.npz',allow_pickle=False) as packed:
        clean=[[packed[f'clean_{i}_{j}'].copy() for j in range(len(arrays))] for i in range(15)]
        if frame['attack_active']:
            alpha=frame['selected_alpha']
            result=[[np.asarray(a+alpha*(packed[f'poison_{c}_{j}'].astype(float)-a),dtype=a.dtype)
                     for j,a in enumerate(g)] if c in task['attackers'] else g
                    for c,g in zip(gen.clients,clean,strict=True)]
        else:result=clean
    return base,result

def inputs(base,gs,gen,rows):
    arrays=arrays_from_export(base,np=np)
    models=[[b.astype(float)-.001*g.astype(float) for b,g in zip(arrays,gradient,strict=True)] for gradient in gs]
    ds=[[a-b.astype(float) for a,b in zip(model,arrays,strict=True)] for model in models]
    indicators=update_indicators(ds,client_ids=gen.clients)
    base_f1=evaluate(base,rows,gen.deps)['macro_f1_all_model_classes']
    exports=[model_with_arrays(base,m) for m in models]
    for x,export in zip(indicators,exports,strict=True):
        x['validation_impact']=base_f1-evaluate(export,rows,gen.deps)['macro_f1_all_model_classes']
    return models,exports,indicators

for source in sources:
    task=source['task'];workspace=SOURCE/task['name'];authenticate(workspace,source['manifest_sha256'])
    gen=Generator(REPO/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid'),cfg)
    rows=read(cfg['validation_path'])['rows']['validation'];pred,confidence=predict(gen.initial,rows,gen.deps)
    correct=[p==r['label'] for p,r in zip(pred,rows,strict=True)]
    auxiliary=[r for r,ok,p in zip(rows,correct,confidence,strict=True) if ok and float(p)>=.90]
    assert len(auxiliary)>0
    plan=DistributedBackdoorPlan.model_validate({**cfg['attack_plan'],'seed':task['seed'],
        'client_components':dict(zip(task['attackers'],[[13],[17],[24]],strict=True))})
    counts=[len(gen.rows[c]) for c in gen.clients];history=[[] for _ in gen.clients]
    for frame in source['rounds']:
        number=frame['round'];prefix=workspace/'rounds'/f'round-{number:03d}'
        base,gs=gradients(prefix,gen,task,frame)
        for h,g in zip(history,gs,strict=True):
            h.append(np.concatenate([a.astype(float).ravel() for a in g]));h[:]=h[-3:]
        models,exports,indicators=inputs(base,gs,gen,rows)
        if task['mode']=='clean':refs[task['cohort'],number]=indicators
        clean_indicators=refs[task['cohort'],number]
        specs=composite['statistics']['indicators'];directions={n:v['direction'] for n,v in specs.items()};weights={n:v['weight'] for n,v in specs.items()}
        reference=build_indicator_references(clean_indicators,directions=directions)
        clean_scores=score_statistical_indicators(clean_indicators,references=reference,weights=weights,z_cap=3.)
        scores=score_statistical_indicators(indicators,references=reference,weights=weights,z_cap=3.)
        options=composite['policies'];cal=options['calibration']
        thresholds=calibrate_policy_thresholds(list(clean_scores.values()),trust_weight=options['composite_trust_weight'],
            statistical_margin=cal['statistical_max_margin'],composite_margin=cal['composite_max_margin'],downweight_quantile=cal['composite_downweight_quantile'])
        trust=TrustSignal(raw_status='software-experiment-admissibility-assumption',admissible=True,risk=0,
                         evaluated_checks=[],failed_checks=[],reasons=['No fresh TPM claim.'])
        masses=[];decisions=[]
        for c,count in zip(gen.clients,counts,strict=True):
            d=next(d for d in decide_admission_policies(trust=trust,statistics=scores[c],
                statistical_threshold=thresholds.statistical_threshold,composite_threshold=thresholds.composite_threshold,
                composite_downweight_threshold=thresholds.composite_downweight_threshold,trust_weight=thresholds.trust_weight)
                if d.policy=='gated_composite')
            mass=count*(.5 if d.status=='accepted_downweighted' else 1.) if d.contributes else 0.
            masses.append(mass);decisions.append({'client':c,'decision':d.model_dump(mode='json'),'mass':mass})
        auxiliary_scores=[evaluate(e,auxiliary,gen.deps)['macro_f1_all_model_classes'] for e in exports]
        target=DEST/task['name']/f'round-{number:03d}'
        save(target/'common-inputs.json',{'base_sha256':sha256_file(prefix/'base-model.json'),
            'gradient_endpoints_sha256':sha256_file(prefix/'gradient-endpoints.npz'),
            'selected_alpha':frame['selected_alpha'],'client_ids':gen.clients,
            'derived_parameter_matrix_sha256':sha256_bytes(derived_json_bytes([[a.tolist() for a in m] for m in models])),
            'auxiliary_rows':len(auxiliary),'auxiliary_f1':auxiliary_scores,
            'composite_decisions':decisions,'thresholds':thresholds.model_dump(mode='json')})
        current=set(task['attackers']) if frame['attack_active'] and frame['selected_alpha']!=0 else set()
        result=[]
        for method in ('gradient_fedavg','literal_eq2','literal_eq3','normalized_eq2_adaptation','flame','weidetect','gated_composite'):
            def calculate():
                if method in ('gradient_fedavg','literal_eq2','literal_eq3','normalized_eq2_adaptation'):
                    model,report=operation(base,gs,history,counts,gen.clients,method)
                    return model,report,None
                if method=='flame':
                    values,report=flame_aggregate(base=arrays_from_export(base,np=np),models=models,client_ids=gen.clients,noise_factor=.01,seed=task['seed']+number)
                    return model_with_arrays(base,values) if values is not None else None,report,set(report.get('selected_client_ids',[]))
                if method=='weidetect':
                    values,report=weidetect_aggregate(models=models,client_ids=gen.clients,validation_f1=auxiliary_scores,keep_count=12,seed=task['seed']+number)
                    return model_with_arrays(base,values),report,set(report['selected_client_ids'])
                positive=sum(x>0 for x in masses)
                if positive<8:return None,{'quorum_satisfied':False,'masses':masses},set()
                values=[sum(m*local[i] for m,local in zip(masses,models,strict=True))/sum(masses) for i in range(len(models[0]))]
                return model_with_arrays(base,values),{'masses':masses,'quorum_satisfied':True},set(c for c,m in zip(gen.clients,masses,strict=True) if m>0)
            try:
                model,report,selected=calculate()
                if model is not None:
                    repeat,repeated_report,_=calculate();assert repeat==model and repeated_report==report
                    metric=outcomes(model,rows,plan,correct,gen.deps)
                    if not np.isfinite(metric['clean']['loss']):raise ValueError('nonfinite evaluation loss')
                    save(target/f'{method}-model.json',model)
                    totals['repeated_aggregations']+=1
                    row={'method':method,'status':'evaluated','metrics':metric,'report':report,
                         'native_client_detection_metric':selected is not None,
                         'manipulated_excluded':len(current-selected) if selected is not None else None,
                         'currently_unmodified_excluded':len((set(gen.clients)-current)-selected) if selected is not None else None,
                         'current_manipulated_count':len(current)}
                    totals['outputs']+=1
                else:
                    row={'method':method,'status':'no_model','report':report};totals['failed_outputs']+=1
            except (ValueError,ArithmeticError,RuntimeError) as e:
                row={'method':method,'status':'failed','error_type':type(e).__name__,'error':str(e)};totals['failed_outputs']+=1
            save(target/f'{method}-result.json',row);result.append(row)
        records.append({'task':task,'round':number,'outputs':result});totals['contexts']+=1
        print(json.dumps({'shared_case':task['name'],'round':number,'counts':totals}),flush=True)
save(DEST/'results.json',{'records':records,'counts':totals})
Generator.close(DEST)
(OUT/'shared-gradient-replayed-results.json').write_bytes((DEST/'results.json').read_bytes())
print('SHARED GRADIENT BASELINES FINISHED',json.dumps(totals),flush=True)
