"""Fit clean-only predictors and inspect already seen development trajectories."""
import json
from pathlib import Path
from study_data import get_observation
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file
from state_conditioned_audit import (fit_state_reference,calibrate_state_threshold,
    detect_state_anomalies,save_model,model_identity)

root=Path.cwd()/'artifacts/revision-state-conditioned-development-v1'
fit=[get_observation(p) for p in sorted((root/'observable-fit').iterdir())]
cal=[get_observation(p) for p in sorted((root/'observable-calibration').iterdir())]
out=root/'analysis-v1';out.mkdir(exist_ok=False)
save(out/'protocol-before-fit.json',{'role':'Development on already seen V2 evaluation seeds; no new held-out claim.',
    'algorithm_sha256':sha256_file(Path(__file__).parent/'state_conditioned_audit.py'),
    'predictors':['conditioned','state-disabled'],'ridge':.1,'risk_quantile':.8,'calibration_scale_margin':1.})
summary=[]
for name,condition in (('conditioned',True),('state-disabled',False)):
    model=fit_state_reference(fit,condition_on_state=condition)
    calibration=calibrate_state_threshold(cal,model)
    save_model(out/f'{name}-model.npz',model)
    save(out/f'{name}-calibration.json',calibration)
    for p in sorted((root/'observable-development').iterdir()):
        result=detect_state_anomalies(get_observation(p),model,calibration)
        save(out/f'{name}-{p.name}.json',result)
        summary.append({'predictor':name,'case':p.name,'status':result['status'],'flagged_clients':result['flagged_clients'],
            'supported_frames':result['supported_frames'],'scores':result.get('client_scores'),
            'threshold':calibration['threshold'],'state_support_limit':calibration['state_support_limit']})
        print(json.dumps(summary[-1]),flush=True)
save(out/'summary.json',{'role':'development','cases':summary})
report=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/state-conditioned-detector-20261103')
(report/'development-summary.json').write_bytes((out/'summary.json').read_bytes())
