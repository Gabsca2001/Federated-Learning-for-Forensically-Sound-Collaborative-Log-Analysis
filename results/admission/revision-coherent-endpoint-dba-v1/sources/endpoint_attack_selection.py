"""Explicit Byzantine poisoned-endpoint construction; not honest gradients."""
from fl_forensics.secure_round import _model_from_export
from fl_forensics.federated_model import train_local,export_state
FACTORS=(0.,.125,.5,1.,2.,4.)
def poisoned_endpoint(initial,rows,weights,seed,deps):
    model=_model_from_export(initial,torch=deps[1],np=deps[0])
    train_local(model=model,rows=rows,class_names=initial['class_names'],class_weights=weights,
        epochs=10,batch_size=128,learning_rate=.001,seed=seed,device_name='cpu',torch=deps[1],np=deps[0])
    return export_state(model,architecture=initial['architecture'],class_names=initial['class_names'])
def select_endpoint_query(queries,clean_f1,maximum_loss=.05):
    if [q['alpha'] for q in queries]!=list(FACTORS):raise ValueError('changed endpoint query budget')
    feasible=[]
    for q in queries:
        if not q['defined']:continue
        m=q['metrics']
        if clean_f1-m['clean']['macro_f1_all_model_classes']<=maximum_loss:
            worst=max(m['complete_trigger']['asr'],*[v['asr'] for v in m['component_triggers'].values()])
            feasible.append((worst,q['alpha']))
    if not feasible:return 0.,{'guard_feasible':False,'feasible_queries':0,'fallback':'Unmodified alpha0; may still pause or fail utility after prior contamination.'}
    return max(feasible)[1],{'guard_feasible':True,'feasible_queries':len(feasible),'fallback':None}
