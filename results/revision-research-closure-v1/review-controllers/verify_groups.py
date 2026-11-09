"""Replay group selection, every removal and every corrected-base continuation."""
from pathlib import Path
import json
import sys

OUT=Path(__file__).parent
sys.path[:0]=[str(OUT.parent/'state-conditioned-detector-20261103'),
              str(OUT.parent/'geometry-detector-20261103'),str(OUT.parent/'group-validation-20261103')]
from study_data import Generator
from policy_data import aggregate_selected
from group_common import load_observable
from revision_dba_experiment import authenticate,save,outcomes,predict
from fl_forensics.canonical import sha256_file
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.group_calibration_v3 import detect_tree_groups
from fl_forensics.preprocessing import derived_json_bytes

REPO=Path.cwd();root=REPO/'artifacts/revision-research-closure-v1/groups'
def read(p):return json.loads(Path(p).read_bytes())

truth=read(root/'evaluation-truth.json')['cases'];effects=read(root/'interventions/results.json')
authenticate(root/'interventions',sha256_file(root/'interventions/manifest.json'))
cfg=read(REPO/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
counts={'selection_cases':0,'source_training_calls_repeated':0,'direct_outputs':0,
        'continuation_branches':0,'continuation_training_calls_repeated':0,'continuation_aggregates':0}
for case in effects['cases']:
    source=next(t for t in truth if t['alias']==case['alias']);task=source['task']
    workspace=root/'cases'/case['alias'];authenticate(workspace,source['manifest_sha256'])
    reference=read(root/'selection'/task['cohort']/'reference.json')
    calibration=read(root/'selection'/task['cohort']/'v3-calibration.json')
    result=detect_tree_groups(load_observable(root/'observable-inputs'/case['alias']),reference,calibration)
    assert result==read(root/'selection'/f'{case["alias"]}-v3.json')
    counts['selection_cases']+=1
    gen=Generator(REPO/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid'),cfg)
    rows=read(cfg['validation_path'])['rows']['validation'];pred,_=predict(gen.initial,rows,gen.deps)
    correct=[p==r['label'] for p,r in zip(pred,rows,strict=True)]
    plan=DistributedBackdoorPlan.model_validate({**cfg['attack_plan'],'seed':task['seed'],
        'client_components':dict(zip(task['attackers'],[[13],[17],[24]],strict=True))})
    for number in (1,10,15):
        p=workspace/'rounds'/f'round-{number:03d}';base=read(p/'base-model.json')
        original,_,local,_=gen.execute(base,task['seed'],number,plan if task['mode']=='distributed' else None)
        assert derived_json_bytes(original)==(p/'global-model.json').read_bytes()
        assert all(derived_json_bytes(e)==(p/'updates'/f'{c}.json').read_bytes() for c,e in zip(gen.clients,local,strict=True))
        counts['source_training_calls_repeated']+=15
    p=workspace/'rounds/round-010';base=read(p/'base-model.json')
    exports=[read(p/'updates'/f'{c}.json') for c in gen.clients]
    for effect in case['interventions']:
        model=aggregate_selected(gen,base,exports,effect['removed'])
        assert outcomes(model,rows,plan,correct,gen.deps)==effect['R10']
        counts['direct_outputs']+=1
        if 'continuation' not in effect:continue
        import hashlib
        key=hashlib.sha256(derived_json_bytes(sorted(effect['removed']))).hexdigest()[:16]
        folder=root/'interventions'/case['alias']/key
        state=model
        for frame in effect['continuation']:
            number=frame['round'];p=folder/'rounds'/f'round-{number:03d}'
            assert derived_json_bytes(state)==(p/'base-model.json').read_bytes()
            _,_,local,_=gen.execute(state,task['seed'],number)
            assert all(derived_json_bytes(e)==(p/'updates'/f'{c}.json').read_bytes() for c,e in zip(gen.clients,local,strict=True))
            state=aggregate_selected(gen,state,local,effect['removed'])
            assert derived_json_bytes(state)==(p/'global-model.json').read_bytes()
            assert outcomes(state,rows,plan,correct,gen.deps)==frame['validation']
            counts['continuation_training_calls_repeated']+=15
            counts['continuation_aggregates']+=1
        counts['continuation_branches']+=1
    print(json.dumps({'verified_group_case':case['alias'],'counts':counts}),flush=True)
record={'status':'verified','counts':counts,'scope':'Every V3 selection, direct removal and corrected-base future repeated using the same implementation. Source local training repeated at rounds1/10/15, not every source round. No new TPM quotes or external implementation audit.'}
save(root.parent/'group-replay.json',record)
(OUT/'group-replay.json').write_bytes((root.parent/'group-replay.json').read_bytes())
print('GROUP REPLAY COMPLETE',json.dumps(counts),flush=True)
