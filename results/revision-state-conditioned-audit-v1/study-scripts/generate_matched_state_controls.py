"""Supplemental null controls fixed before any held-out detector inference.

Replay clean local responses at the attacked trajectory's incoming checkpoints.
These are conditional context probes, not a repaired autoregressive FL history.
"""
from pathlib import Path
import numpy as np
from study_data import Generator,read,export_observation,flat
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export

repo=Path.cwd();lab=repo/'artifacts/revision-state-conditioned-heldout-v1'
assert not (lab/'selections/selection-closure.json').exists()
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
mapping=read(lab/'private-evaluation-map-before-generation.json')
save(lab/'matched-state-control-protocol-before-generation.json',{'profile':'heldout-matched-state-clean-controls-v1',
    'purpose':'Test false alarms on wholly benign client executions responding to actually contaminated incoming checkpoints.',
    'rule':'For every predeclared attacked case, retain each actual incoming W, train all clients with original unmodified rows and the same local seeds; no outputs feed the next checkpoint.',
    'model_closure_sha256':sha256_file(lab/'models/model-closure.json'),
    'design_timing':'Supplemental design frozen before held-out detector inference; method and thresholds unchanged.',
    'controller_sha256':sha256_file(Path(__file__)),'new_local_training_calls':900,
    'independence':'Matched to the six attacked sources; frames overlap their clean pairs at the initial checkpoint and are not independent extra trials.'})
index=read(lab/'evaluation-input-index.json');supplemental=[]
generators={cohort:Generator(repo/'artifacts'/name,cfg) for cohort,name in
    [('iid','m3-data24-parquet-iid-local-test-v1'),('non-iid','m3-data24-parquet-non-iid')]}
for case in mapping['cases']:
    if case['mode']!='distributed':continue
    cohort=case['cohort'];generator=generators[cohort];case_id='control-'+case['id']
    destination=lab/'private-generation/matched-state-controls'/case_id
    save(destination/'protocol.json',{'profile':'conditional-clean-state-response-bank-v1',
        'source_case_id':case['id'],'seed':case['seed'],'original_data_available_only_to_generator':True})
    states=[];updates=[];commits=[]
    for number in range(1,11):
        source=lab/'private-generation/heldout'/case['id']/'rounds'/f'round-{number:03d}'
        base=read(source/'base-model.json');result,deltas,exports,records=generator.execute(base,case['seed'],number)
        prefix=destination/f'context-{number:03d}';save(prefix/'base-model.json',base)
        for client,local in zip(generator.clients,exports,strict=True):save(prefix/'updates'/f'{client}.json',local)
        save(prefix/'execution.json',records)
        states.append(flat(arrays_from_export(base,np=np)));updates.append(np.stack([flat(d) for d in deltas]))
        commits.append({'base_model_sha256':sha256_file(prefix/'base-model.json'),
            'local_model_sha256':[sha256_file(prefix/'updates'/f'{c}.json') for c in generator.clients]})
        print({'matched_state_control':case_id,'context':number},flush=True)
    generator.close(destination)
    exported=lab/'observable-inputs/matched-state-controls'/case_id
    export_observation(exported,{'states':np.stack(states),'updates':np.stack(updates),'clients':generator.clients,
        'sizes':[a.size for a in arrays_from_export(base,np=np)],'source':commits})
    index['cohorts'][cohort]['cases'].append({'id':case_id,'path':exported.relative_to(lab).as_posix()})
    supplemental.append({**case,'id':case_id,'source_case_id':case['id'],'mode':'matched-state-clean','attackers':[]})
save(lab/'private-matched-state-control-map.json',{'cases':supplemental})
save(lab/'evaluation-with-matched-controls-input-index.json',index)
save(lab/'matched-state-control-input-closure.json',{'index_sha256':sha256_file(lab/'evaluation-with-matched-controls-input-index.json'),
    'files':{p.relative_to(lab).as_posix():sha256_file(p) for p in (lab/'observable-inputs/matched-state-controls').rglob('*') if p.is_file()},
    'model_closure_sha256':sha256_file(lab/'models/model-closure.json'),'new_local_training_calls':900})
print('MATCHED STATE CONTROLS READY',flush=True)
