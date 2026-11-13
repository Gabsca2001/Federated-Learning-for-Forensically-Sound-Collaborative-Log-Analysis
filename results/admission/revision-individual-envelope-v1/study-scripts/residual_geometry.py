"""Client-specific, tensor-geometry residual evidence from observable models.

Groups cover every row and column of every matrix and every bias tensor. No
attack feature, label or original client row is an input to this empirical head.
"""
from __future__ import annotations

import hashlib
import json
import numpy as np

from .state_conditioned_audit import _validate, model_identity

PROFILE = "client-residual-geometry-v1"
VIEWS = ("conditioned", "state-disabled")


def parameter_groups(shapes):
    groups=[];offset=0
    for tensor,shape in enumerate(shapes):
        if not shape or len(shape)>2 or any(type(n) is not int or n<1 for n in shape):
            raise ValueError("only nonempty vector/matrix parameter shapes are supported")
        size=int(np.prod(shape));indices=np.arange(offset,offset+size).reshape(shape)
        if len(shape)==2:
            for axis in (0,1):
                for number in range(shape[axis]):
                    groups.append({"id":f"tensor-{tensor}-axis-{axis}-{number}",
                        "indices":np.take(indices,number,axis=axis).reshape(-1).tolist()})
        else:groups.append({"id":f"tensor-{tensor}-vector","indices":indices.tolist()})
        offset+=size
    return groups


def centered_residuals(observation, model):
    x,y,schema,frames=_validate(observation,model["schema"])
    xc=x-model["xmean"];design=xc/model["state_scale"]
    kernel=design@model["design"].T/len(schema["sizes"])
    predicted=np.broadcast_to(model["ymean"],y.shape).copy()
    ends=np.cumsum([0,*schema["sizes"]])
    if model["condition_on_state"]:
        for layer,(a,b) in enumerate(zip(ends[:-1],ends[1:],strict=True)):
            predicted[:,:,a:b]+=xc[:,None,a:b]*model["slopes"][None,:,layer,None]
        predicted+=(kernel@model["coefficients"].reshape(len(model["design"]),-1)).reshape(y.shape)
    residual=y-predicted;residual-=np.median(residual,axis=1)[:,None,:]
    kxx=np.square(design).sum(axis=1)/len(schema["sizes"])
    explained=np.einsum("ni,ij,nj->n",kernel,model["inverse"],kernel)
    support=np.sqrt(np.maximum(0.,kxx-explained))
    return residual,support,frames


def _group_risk(residual,center,scale,groups):
    z=(residual-center)/scale
    return np.log1p(np.stack([np.sqrt(np.mean(np.square(z[:,:,g["indices"]]),axis=2)) for g in groups],axis=2))


def fit_geometry(normalizer_observations, threshold_observations, models, shapes):
    if set(models)!=set(VIEWS) or len(normalizer_observations)<2 or len(threshold_observations)<2:
        raise ValueError("separate clean normalization and null controls are required")
    schema=models[VIEWS[0]]["schema"]
    if models[VIEWS[1]]["schema"]!=schema or [int(np.prod(s)) for s in shapes]!=schema["sizes"]:
        raise ValueError("geometry/model schema mismatch")
    if not models['conditioned']['condition_on_state'] or models['state-disabled']['condition_on_state']:
        raise ValueError("predictor view roles differ")
    groups=parameter_groups(shapes);result={"profile":PROFILE,"schema":schema,"shapes":shapes,"groups":groups,
        "model_ids":{v:model_identity(models[v]) for v in VIEWS},"normalizer_frame_ids":[],"threshold_frame_ids":[],
        "automatic_deployment_validated":False,"semantic_malice_proved":False}
    support_limits={};null_group=[];null_tensor=[]
    for view in VIEWS:
        norm=[centered_residuals(o,models[view]) for o in normalizer_observations]
        ids=[f for r,s,frames in norm for f in frames]
        if len(ids)!=len(set(ids)):raise ValueError("normalizer overlap")
        residual=np.concatenate([r for r,s,f in norm]);center=np.median(residual,axis=0)
        scale=1.4826*np.median(np.abs(residual-center),axis=0)
        ends=np.cumsum([0,*schema['sizes']])
        for a,b in zip(ends[:-1],ends[1:],strict=True):
            floor=np.maximum(1e-8,.1*np.median(scale[:,a:b],axis=1))
            scale[:,a:b]=np.maximum(scale[:,a:b],floor[:,None])
        gr=_group_risk(residual,center,scale,groups)
        gc=np.median(gr,axis=0);gs=np.maximum(.05,1.4826*np.median(np.abs(gr-gc),axis=0))
        result[f'{view}_center']=center;result[f'{view}_scale']=scale
        result[f'{view}_group_center']=gc;result[f'{view}_group_scale']=gs
        null=[];tensor=[];null_ids=[];distances=[]
        for observation in threshold_observations:
            r,s,frames=centered_residuals(observation,models[view]);null_ids.extend(frames);distances.extend(s)
            null.append(np.maximum(0.,(_group_risk(r,center,scale,groups)-gc)/gs))
            # Preserve the old tensor-level score as a separate ablation.
            old=np.stack([np.linalg.norm(r[:,:,a:b],axis=2)/models[view]['output_scale'][None,:,i]
                for i,(a,b) in enumerate(zip(ends[:-1],ends[1:],strict=True))],axis=2)
            tensor.append(np.log1p(old.max(axis=2)))
        if set(ids)&set(null_ids):raise ValueError("normalizer/null overlap")
        if view==VIEWS[0]:result['normalizer_frame_ids']=sorted(ids);result['threshold_frame_ids']=sorted(set(null_ids))
        else:
            if result['normalizer_frame_ids']!=sorted(ids) or result['threshold_frame_ids']!=sorted(set(null_ids)):
                raise ValueError('view frame bindings differ')
        support_limits[view]=float(max(max(s) for r,s,f in norm))
        support_limits[view]=max(support_limits[view],float(max(distances)))
        null_group.append(np.concatenate(null));null_tensor.append(np.concatenate(tensor))
    joint=np.minimum(null_group[0],null_group[1])
    result['group_limits']=joint.max(axis=0)+1.
    result['tensor_risk_limits']=np.stack([r.max(axis=0) for r in null_tensor],axis=1)+.05
    result['state_support_limits']=support_limits
    return result


def geometry_scores(observation,models,reference):
    if reference.get('profile')!=PROFILE or set(models)!=set(VIEWS):raise ValueError('unknown geometry reference')
    scores=[];tensor=[];supports=[];frames=None
    ends=np.cumsum([0,*reference['schema']['sizes']])
    for view in VIEWS:
        if model_identity(models[view])!=reference['model_ids'][view]:raise ValueError('changed predictor')
        r,s,f=centered_residuals(observation,models[view])
        if frames is not None and f!=frames:raise ValueError('view observation mismatch')
        frames=f;supports.append(s)
        group=_group_risk(r,reference[f'{view}_center'],reference[f'{view}_scale'],reference['groups'])
        scores.append(np.maximum(0.,(group-reference[f'{view}_group_center'])/reference[f'{view}_group_scale']))
        old=np.stack([np.linalg.norm(r[:,:,a:b],axis=2)/models[view]['output_scale'][None,:,i]
            for i,(a,b) in enumerate(zip(ends[:-1],ends[1:],strict=True))],axis=2)
        tensor.append(np.log1p(old.max(axis=2)))
    joint=np.minimum(scores[0],scores[1]);excess=joint-reference['group_limits']
    supported=np.logical_and.reduce([s<=reference['state_support_limits'][v]*(1+1e-12)+1e-12 for v,s in zip(VIEWS,supports,strict=True)])
    return {'group_excess':excess,'tensor_risk':np.stack(tensor,axis=2),'supported':supported,'frame_ids':frames,
        'state_support_distances':np.stack(supports,axis=1)}


def save_geometry(path,reference):
    metadata={k:v for k,v in reference.items() if not isinstance(v,np.ndarray)}
    arrays={k:v for k,v in reference.items() if isinstance(v,np.ndarray)}
    np.savez_compressed(path,metadata=np.asarray(json.dumps(metadata,sort_keys=True)),**arrays)


def load_geometry(path):
    with np.load(path,allow_pickle=False) as saved:
        return {**json.loads(str(saved['metadata'])),**{k:saved[k] for k in saved.files if k!='metadata'}}
