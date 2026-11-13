"""Descriptive export accounting; zero scores are not identity classifications."""
from pathlib import Path
import json,hashlib,numpy as np
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
def read(p):return json.loads(p.read_bytes())
def main():
    for directory in ('revision-coherent-dba-v1','revision-coherent-endpoint-dba-v1'):
        D=R/'results'/directory;assert read(D/'verification.json')['status']=='full_trajectory_and_query_replay_verified'
        assert not (D/'submission-observations.json').exists()
        p=read(D/'protocol-before-training.json');cases=[]
        clean={}
        for task in p['tasks']:
            if task['mode']=='clean':clean[(task['seed'],task['method'])]=read(D/'evidence/histories'/task['name']/'result.json')
        for task in p['tasks']:
            if task['mode']=='clean':continue
            r=read(D/'evidence/histories'/task['name']/'result.json');ctrl=clean[(task['seed'],task['method'])]
            clean_metrics={row['round']:row['validation'] for row in ctrl['journal'] if row['event']['decision']=='commit'}
            counts={'selected_manipulated_exports':0,'selected_unmodified_exports':0,'manipulated_zero_score':0,
                'unmodified_zero_score':0,'zero_score_count_undefined_rounds':0,'active_selected_alpha_zero_rounds':0,
                'adaptive_queries':0,'blocked_queries':0,'nonzero_guard_compliant_queries':0}
            for row in r['journal']:
                changed=set(row['actually_manipulated_clients']);counts['selected_manipulated_exports']+=len(changed)
                counts['selected_unmodified_exports']+=len(row['event']['received_clients'])-len(changed)
                counts['active_selected_alpha_zero_rounds']+=row['round']<=10 and row['selected_alpha']==0
                agg=row['event']['aggregation']
                if agg:
                    scores=agg.get('scores') or agg.get('coefficients')
                    counts['manipulated_zero_score']+=sum(scores[c]==0 for c in changed)
                    counts['unmodified_zero_score']+=sum(v==0 for c,v in scores.items() if c not in changed)
                else:counts['zero_score_count_undefined_rounds']+=1
                for q in row['queries']:
                    counts['adaptive_queries']+=1;counts['blocked_queries']+=not q['defined']
                    if q['defined'] and q['alpha']>0 and clean_metrics[row['round']]['clean']['macro_f1_all_model_classes']-q['metrics']['clean']['macro_f1_all_model_classes']<=.05:
                        counts['nonzero_guard_compliant_queries']+=1
            residual=None
            if r['complete']:
                a=read(D/'evidence/histories'/task['name']/'last-committed-checkpoint.json')
                b=read(D/'evidence/histories'/ctrl['task']['name']/'last-committed-checkpoint.json')
                total=sum(np.sum((np.asarray(x['values'],dtype=float)-np.asarray(y['values'],dtype=float))**2) for x,y in zip(a['parameters'],b['parameters'],strict=True))
                residual=float(np.sqrt(total))
            cases.append({'history':task['name'],'method':task['method'],'mode':task['mode'],'seed':task['seed'],
                'complete':r['complete'],'committed_rounds':r['committed_rounds'],**counts,'final_parameter_l2_to_own_clean':residual})
        result={'scope':'Selected current exports and shadow queries. Zero score is a local numerical decision, not proof of malicious identity. Paused rounds are counted as observed submissions, not completed training. Residual parameter distance alone proves no harm or unlearning.',
            'cases':cases,'source_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        (D/'submission-observations.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({'study':directory,'cases':len(cases),'selected_manipulated_exports':sum(c['selected_manipulated_exports'] for c in cases),
            'blocked_queries':sum(c['blocked_queries'] for c in cases)}))
if __name__=='__main__':main()
