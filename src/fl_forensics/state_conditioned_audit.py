"""State-conditioned update consistency from server-visible models only.

This empirical predictor handles multi-epoch optimizer deltas directly; it is not
a gradient/Hessian implementation of FLDetector or proof of malicious intent.
"""
from __future__ import annotations

import hashlib
import json
import numpy as np

PROFILE='state-conditioned-update-consistency-v1'
ALLOWED={'states','updates','clients','sizes','profile','frames','observations_sha256',
         'source_commitments','includes_raw_client_rows','includes_attack_labels','cohort_id'}


def _validate(observation, schema=None):
    if set(observation)-ALLOWED:
        raise ValueError('detector accepts only the observable schema')
    if observation.get('includes_raw_client_rows',False) or observation.get('includes_attack_labels',False):
        raise ValueError('private rows or attack labels are not detector inputs')
    clients=list(observation['clients']);sizes=list(observation['sizes'])
    states=np.asarray(observation['states'],dtype=np.float64)
    updates=np.asarray(observation['updates'],dtype=np.float64)
    if len(clients)<3 or clients!=sorted(set(clients)) or not sizes or any(not isinstance(n,(int,np.integer)) or n<=0 for n in sizes):
        raise ValueError('invalid client/tensor schema')
    if states.ndim!=2 or updates.ndim!=3 or len(states)==0 or updates.shape!=(len(states),len(clients),sum(sizes)) or states.shape[1]!=sum(sizes):
        raise ValueError('inconsistent observable shapes')
    if not np.isfinite(states).all() or not np.isfinite(updates).all():
        raise ValueError('nonfinite model observations')
    current={'clients':clients,'sizes':sizes,'cohort_id':observation.get('cohort_id','unspecified')}
    if schema is not None and schema!=current:
        raise ValueError('cohort/client/tensor schema differs from the fitted reference')
    frames=[]
    for state,update in zip(states,updates,strict=True):
        h=hashlib.sha256();h.update(state.astype('<f8').tobytes());h.update(update.astype('<f8').tobytes());frames.append(h.hexdigest())
    if len(set(frames))!=len(frames):raise ValueError('duplicate observable frame')
    return states,updates,current,frames


def model_identity(model):
    h=hashlib.sha256()
    for key in sorted(model):
        h.update(key.encode())
        value=model[key]
        if isinstance(value,np.ndarray):
            h.update(str(value.shape).encode());h.update(value.astype('<f8').tobytes())
        else:h.update(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
    return h.hexdigest()


def fit_state_reference(clean_observations,*,condition_on_state=True,ridge=.1):
    if len(clean_observations)<2 or not np.isfinite(ridge) or ridge<=0:raise ValueError('invalid clean fit')
    states=[];updates=[];ids=[];schema=None
    for observation in clean_observations:
        x,y,current,frames=_validate(observation,schema)
        if schema is None:schema=current
        if set(ids)&set(frames):raise ValueError('overlapping fit frames')
        states.append(x);updates.append(y);ids.extend(frames)
    x=np.concatenate(states);y=np.concatenate(updates)
    xmean=x.mean(axis=0);ymean=y.mean(axis=0);xc=x-xmean;yc=y-ymean
    sizes=schema['sizes'];ends=np.cumsum([0,*sizes]);slopes=np.zeros((len(schema['clients']),len(sizes)))
    state_scale=np.empty(x.shape[1]);output_scale=np.empty((len(schema['clients']),len(sizes)))
    residual=yc.copy()
    for layer,(a,b) in enumerate(zip(ends[:-1],ends[1:],strict=True)):
        spread=float(np.median(np.linalg.norm(xc[:,a:b],axis=1)))
        state_scale[a:b]=max(spread,1e-8)
        output_scale[:,layer]=np.maximum(np.median(np.linalg.norm(y[:,:,a:b],axis=2),axis=0),1e-6)
        if condition_on_state:
            denominator=float(np.square(xc[:,a:b]).sum())
            if denominator>1e-16:
                slopes[:,layer]=np.clip(np.einsum('np,ncp->c',xc[:,a:b],yc[:,:,a:b])/denominator,-2.,2.)
                residual[:,:,a:b]-=xc[:,None,a:b]*slopes[None,:,layer,None]
    design=xc/state_scale
    gram=design@design.T/len(sizes)
    inverse=np.linalg.inv(gram+ridge*np.eye(len(x)))
    coefficients=(inverse@residual.reshape(len(x),-1)).reshape(y.shape) if condition_on_state else np.zeros_like(y)
    return {'profile':PROFILE,'schema':schema,'condition_on_state':bool(condition_on_state),
        'ridge':float(ridge),'fit_frame_ids':ids,'xmean':xmean,'ymean':ymean,
        'state_scale':state_scale,'output_scale':output_scale,'slopes':slopes,
        'design':design,'inverse':inverse,'coefficients':coefficients}


def residual_scores(observation,model):
    if model.get('profile')!=PROFILE:raise ValueError('unknown predictor')
    x,y,schema,ids=_validate(observation,model['schema'])
    xc=x-model['xmean'];design=xc/model['state_scale'];layers=len(schema['sizes'])
    kernel=design@model['design'].T/layers
    predicted=np.broadcast_to(model['ymean'],y.shape).copy()
    ends=np.cumsum([0,*schema['sizes']])
    if model['condition_on_state']:
        for layer,(a,b) in enumerate(zip(ends[:-1],ends[1:],strict=True)):
            predicted[:,:,a:b]+=xc[:,None,a:b]*model['slopes'][None,:,layer,None]
        predicted+=(kernel@model['coefficients'].reshape(len(model['design']),-1)).reshape(y.shape)
    residual=y-predicted
    common=np.median(residual,axis=1)
    centered=residual-common[:,None,:]
    layer_errors=[]
    for layer,(a,b) in enumerate(zip(ends[:-1],ends[1:],strict=True)):
        layer_errors.append(np.linalg.norm(centered[:,:,a:b],axis=2)/model['output_scale'][None,:,layer])
    risk=np.log1p(np.max(np.stack(layer_errors,axis=2),axis=2))
    kxx=np.square(design).sum(axis=1)/layers
    explained=np.einsum('ni,ij,nj->n',kernel,model['inverse'],kernel)
    support_distance=np.sqrt(np.maximum(0.,kxx-explained))
    return {'risk':risk,'state_support_distance':support_distance,'frame_ids':ids,
        'common_residual_l2':np.linalg.norm(common,axis=1)}


def calibrate_state_threshold(clean_observations,model):
    if len(clean_observations)<2:raise ValueError('separate clean calibration is required')
    frame_ids=[];risks=[];maxima=[];horizons=[]
    for observation in clean_observations:
        scored=residual_scores(observation,model)
        horizons.append(len(scored['risk']))
        if len(scored['risk'])<3:raise ValueError('insufficient calibration horizon')
        if set(scored['frame_ids'])&(set(frame_ids)|set(model['fit_frame_ids'])):raise ValueError('fit/calibration overlap')
        frame_ids.extend(scored['frame_ids'])
        risks.append(np.quantile(scored['risk'],.8,axis=0,method='linear'))
        maxima.append(float(scored['state_support_distance'].max()))
    if len(set(horizons))!=1:raise ValueError('calibration horizons differ')
    risks=np.stack(risks)
    centers=np.median(risks,axis=0)
    scales=np.maximum(.05,1.4826*np.median(np.abs(risks-centers),axis=0))
    standardized=np.maximum(0.,(risks-centers)/scales)
    return {'profile':PROFILE,'model_identity':model_identity(model),'calibration_frame_ids':frame_ids,
        'centers':centers.tolist(),'scales':scales.tolist(),'threshold':float(standardized.max())+1.,
        'state_support_limit':max(maxima),'calibration_case_count':len(risks),
        'risk_quantile':.8,'expected_horizon':horizons[0],'minimum_supported_frames':3,'calibration_scale_margin':1.,'automatic_exclusion_validated':False,
        'interpretation':'Empirical clean campaign maximum over client scores; fitting and calibration are disjoint. No general low false-positive probability follows from this small calibration sample.'}


def detect_state_anomalies(observation,model,calibration):
    if calibration.get('profile')!=PROFILE or calibration.get('model_identity')!=model_identity(model):raise ValueError('calibration does not bind this predictor')
    scored=residual_scores(observation,model)
    if calibration.get('risk_quantile')!=.8 or calibration.get('minimum_supported_frames')!=3 or calibration.get('calibration_scale_margin')!=1.:
        raise ValueError('changed scoring protocol')
    if len(scored['risk'])!=calibration.get('expected_horizon'):
        raise ValueError('the complete calibrated horizon is required')
    center=np.asarray(calibration['centers'],dtype=np.float64)
    scale=np.asarray(calibration['scales'],dtype=np.float64)
    if center.shape!=(len(model['schema']['clients']),) or scale.shape!=center.shape or not np.isfinite(center).all() or not np.isfinite(scale).all() or np.any(scale<.05):
        raise ValueError('invalid client score normalization')
    if set(scored['frame_ids'])&(set(model['fit_frame_ids'])|set(calibration['calibration_frame_ids'])):raise ValueError('evaluation reuses clean fit/calibration frames')
    threshold=float(calibration['threshold']);limit=float(calibration['state_support_limit'])
    if not np.isfinite(threshold) or threshold<0 or not np.isfinite(limit) or limit<0:raise ValueError('invalid calibration')
    supported=scored['state_support_distance']<=limit*(1.+1e-12)+1e-12
    if int(supported.sum())<calibration['minimum_supported_frames']:
        return {'profile':PROFILE,'status':'abstained','reason':'Insufficient clean-calibrated state support',
            'supported_frames':int(supported.sum()),'total_frames':len(supported),'flagged_clients':[],
            'automatic_exclusion_validated':False,'intentional_collusion_proved':False}
    campaign_risk=np.quantile(scored['risk'][supported],.8,axis=0,method='linear')
    scores=np.maximum(0.,(campaign_risk-np.asarray(calibration['centers']))/np.asarray(calibration['scales']))
    clients=model['schema']['clients'];flagged=[c for c,s in zip(clients,scores,strict=True) if s>threshold]
    return {'profile':PROFILE,'status':'evaluated','condition_on_state':model['condition_on_state'],
        'flagged_clients':flagged,'multi_client_anomaly_hypotheses':[flagged] if len(flagged)>=2 else [],
        'client_scores':dict(zip(clients,map(float,scores),strict=True)),'threshold':threshold,
        'supported_frames':int(supported.sum()),'total_frames':len(supported),
        'frame_risks':scored['risk'].tolist(),'state_support_distances':scored['state_support_distance'].tolist(),
        'common_residual_l2':scored['common_residual_l2'].tolist(),
        'automatic_exclusion_validated':False,'intentional_collusion_proved':False,
        'interpretation':'Local departures from an empirical clean state-response predictor. A multi-client anomaly set is not proof of coordination or malicious intent; evaluate joint/single effects separately.'}


def save_model(path,model):
    metadata={k:v for k,v in model.items() if not isinstance(v,np.ndarray)}
    arrays={k:v for k,v in model.items() if isinstance(v,np.ndarray)}
    np.savez_compressed(path,metadata=np.asarray(json.dumps(metadata,sort_keys=True)),**arrays)


def load_model(path):
    with np.load(path,allow_pickle=False) as saved:
        return {**json.loads(str(saved['metadata'])),**{k:saved[k] for k in saved.files if k!='metadata'}}
