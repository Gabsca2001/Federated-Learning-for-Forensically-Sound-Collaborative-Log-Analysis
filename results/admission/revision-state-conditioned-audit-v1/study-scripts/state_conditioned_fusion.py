"""Two-view update consistency; calibrate the joint evidence on clean cases only."""
import hashlib
import json
import numpy as np
from state_conditioned_audit import (model_identity,residual_scores,detect_state_anomalies)

PROFILE='dual-view-state-update-consistency-v1'


def _digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def calibrate_dual_view(observations,models,calibrations):
    if set(models)!= {'conditioned','state-disabled'} or set(calibrations)!=set(models):raise ValueError('both predictor views are required')
    if models['conditioned']['schema']!=models['state-disabled']['schema']:raise ValueError('view cohort schemas differ')
    case_scores=[]
    for observation in observations:
        standardized=[]
        for key in ('conditioned','state-disabled'):
            result=residual_scores(observation,models[key]);cal=calibrations[key]
            if cal['model_identity']!=model_identity(models[key]):raise ValueError('leaf model identity mismatch')
            if set(result['frame_ids'])-set(cal['calibration_frame_ids']):raise ValueError('joint calibration must use exactly the declared clean calibration data')
            risk=np.quantile(result['risk'],.8,axis=0,method='linear')
            standardized.append(np.maximum(0.,(risk-np.asarray(cal['centers']))/np.asarray(cal['scales'])))
        case_scores.append(np.sqrt(standardized[0]*standardized[1]))
    if len(case_scores)<2:raise ValueError('insufficient clean joint calibration')
    return {'profile':PROFILE,'model_ids':{k:model_identity(m) for k,m in models.items()},
        'calibration_ids':{k:_digest(c) for k,c in calibrations.items()},
        'threshold':float(np.asarray(case_scores).max())+1.,'clean_case_count':len(case_scores),
        'score':'Geometric mean of nonnegative client scores from state-conditioned and state-disabled residual predictors.',
        'clean_scale_margin':1.,'automatic_exclusion_validated':False,'intentional_collusion_proved':False}


def detect_dual_view(observation,models,calibrations,joint_calibration):
    if joint_calibration.get('profile')!=PROFILE:raise ValueError('unknown dual-view profile')
    for key in ('conditioned','state-disabled'):
        if joint_calibration['model_ids'].get(key)!=model_identity(models[key]) or joint_calibration['calibration_ids'].get(key)!=_digest(calibrations[key]):raise ValueError('changed calibrated view')
    leaves={key:detect_state_anomalies(observation,models[key],calibrations[key]) for key in ('conditioned','state-disabled')}
    if any(result['status']!='evaluated' for result in leaves.values()):
        return {'profile':PROFILE,'status':'abstained','flagged_clients':[],'reason':'Insufficient state support in at least one view','views':leaves,'automatic_exclusion_validated':False}
    clients=models['conditioned']['schema']['clients']
    scores={c:float(np.sqrt(leaves['conditioned']['client_scores'][c]*leaves['state-disabled']['client_scores'][c])) for c in clients}
    threshold=float(joint_calibration['threshold'])
    if not np.isfinite(threshold) or threshold<0:raise ValueError('invalid dual-view threshold')
    flagged=[c for c in clients if scores[c]>threshold]
    return {'profile':PROFILE,'status':'evaluated','client_scores':scores,'threshold':threshold,
        'flagged_clients':flagged,'multi_client_anomaly_hypotheses':[flagged] if len(flagged)>=2 else [],
        'views':leaves,'automatic_exclusion_validated':False,'intentional_collusion_proved':False,
        'interpretation':'Jointly anomalous client updates; candidate sets require separate joint/single counterfactual assessment. No raw client rows, attack identities or ASR enter this function.'}
