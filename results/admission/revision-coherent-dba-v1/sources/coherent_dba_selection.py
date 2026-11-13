"""Fixed-budget targeted query selection and compact poisoning commitments."""
import hashlib,json,math

ALPHAS=(0.,1.,4.,16.,64.,256.)

def worst_asr(metric):
    return max(metric['complete_trigger']['asr'],*[v['asr'] for v in metric['component_triggers'].values()])

def select_query(queries,clean_f1,maximum_loss=.05):
    if [q['alpha'] for q in queries]!=list(ALPHAS):raise ValueError('changed adaptive query budget')
    feasible=[]
    for q in queries:
        if not q['defined']:continue
        m=q['metrics'];loss=clean_f1-m['clean']['macro_f1_all_model_classes']
        if loss<=maximum_loss:feasible.append((worst_asr(m),q['alpha']))
    if not feasible:return 0.,{'guard_feasible':False,'feasible_queries':0,'fallback':'Unmodified alpha0; may still pause or fail utility after prior contamination.'}
    return max(feasible)[1],{'guard_feasible':True,'feasible_queries':len(feasible),'fallback':None}

def poison_commitment(record):
    ids=record['poisoned_window_ids']
    payload=json.dumps(sorted(ids),separators=(',',':')).encode()
    return {k:v for k,v in record.items() if k!='poisoned_window_ids'}|{
        'poisoned_row_count':len(ids),'poisoned_ids_sha256':hashlib.sha256(payload).hexdigest()}
