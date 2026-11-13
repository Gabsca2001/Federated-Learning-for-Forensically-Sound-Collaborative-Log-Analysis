import json
from pathlib import Path
from study_data import get_observation
from state_conditioned_audit import load_model
from state_conditioned_fusion import calibrate_dual_view,detect_dual_view
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file

root=Path.cwd()/'artifacts/revision-state-conditioned-development-v1'
old=root/'analysis-v1';out=root/'fusion-analysis-v1';out.mkdir(exist_ok=False)
models={key:load_model(old/f'{key}-model.npz') for key in ('conditioned','state-disabled')}
calibrations={key:json.loads((old/f'{key}-calibration.json').read_bytes()) for key in models}
observations=[get_observation(p) for p in sorted((root/'observable-calibration').iterdir())]
save(out/'design-before-evaluation.json',{'role':'Development only. Joint architecture selected after inspecting individual view development trade-offs; threshold remains clean-only.',
    'algorithm_sha256':sha256_file(Path(__file__).parent/'state_conditioned_fusion.py'),'clean_scale_margin':1.,'rule':'Geometric mean of leaf standardized scores.'})
joint=calibrate_dual_view(observations,models,calibrations);save(out/'calibration.json',joint)
summary=[]
for p in sorted((root/'observable-development').iterdir()):
    result=detect_dual_view(get_observation(p),models,calibrations,joint);save(out/f'{p.name}.json',result)
    summary.append({'case':p.name,'status':result['status'],'flagged_clients':result['flagged_clients'],
        'scores':result.get('client_scores'),'threshold':joint['threshold']})
    print(json.dumps(summary[-1]),flush=True)
save(out/'summary.json',{'role':'development','cases':summary})
target=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/state-conditioned-detector-20261103')
(target/'fusion-development-summary.json').write_bytes((out/'summary.json').read_bytes())
