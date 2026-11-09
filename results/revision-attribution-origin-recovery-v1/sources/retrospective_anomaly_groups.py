"""Separate individual persistent anomaly from shared temporal activity.

Research hypotheses only. Concurrent abnormal updates do not establish collusion.
Fit/calibration contain only clean observable summaries, never attacker labels.
"""
from itertools import combinations
import numpy as np
from coherent_gradient_protocol import digest
from fl_forensics.group_calibration_v2 import _maximal_cliques
from fl_forensics.retrospective_groups import pair_descriptors

PROFILE='persistent-anomaly-coactivity-v4'
FEATURES=('log_relative_norm','validation_impact')
FLOORS={'log_relative_norm':.05,'validation_impact':.005}


def observations(frames):
    if len(frames)!=10:raise ValueError('requires exactly ten ordered observation rounds')
    if [r['round_number'] for r in frames]!=list(range(1,11)):raise ValueError('changed observation window')
    clients=frames[0]['client_ids']
    if len(clients)!=15 or len(set(clients))!=15:raise ValueError('requires declared fifteen-client roster')
    matrix=[]
    for r in frames:
        if r['client_ids']!=clients or [i['client_id'] for i in r['indicators']]!=clients:
            raise ValueError('unstable client/indicator population')
        values=[]
        for x in r['indicators']:
            n=float(x['relative_norm']);v=float(x['validation_impact'])
            if not np.isfinite(n) or n<0 or not np.isfinite(v):raise ValueError('invalid anomaly observable')
            values.append([float(np.log1p(n)),v])
        matrix.append(values)
    return clients,np.asarray(matrix,dtype=float)


def campaign_id(frames):
    clients,x=observations(frames)
    return digest(dict(clients=clients,values=x.tolist()))


def fit_reference(clean_campaigns):
    if len(clean_campaigns)<2:raise ValueError('requires two clean fit campaigns')
    ids=[campaign_id(c) for c in clean_campaigns]
    if len(set(ids))!=len(ids):raise ValueError('duplicate fit observables')
    x=np.concatenate([observations(c)[1].reshape(-1,2) for c in clean_campaigns])
    channels={}
    for k,name in enumerate(FEATURES):
        center=float(np.median(x[:,k]));scale=max(FLOORS[name],1.4826*float(np.median(np.abs(x[:,k]-center))))
        channels[name]=dict(center=center,scale=scale)
    return dict(profile=PROFILE,fit_campaign_ids=ids,features=list(FEATURES),channels=channels,
        labels_used=False,reference_scope='Pooled clean client observations, independent of client-ID-specific pair distributions.')


def scores(frames,reference):
    if reference.get('profile')!=PROFILE or reference.get('labels_used') is not False or reference.get('features')!=list(FEATURES):
        raise ValueError('unknown or label-informed reference')
    clients,x=observations(frames);z=[]
    for k,name in enumerate(FEATURES):
        c=reference['channels'][name]
        if not np.isfinite(c['center']) or not np.isfinite(c['scale']) or c['scale']<FLOORS[name]:raise ValueError('invalid reference scale')
        z.append(np.maximum(0.,(x[:,:,k]-c['center'])/c['scale']))
    return clients,np.maximum.reduce(z)


def calibrate(clean_campaigns,reference):
    if len(clean_campaigns)<3:raise ValueError('requires three separate calibration campaigns')
    ids=[campaign_id(c) for c in clean_campaigns]
    if len(set(ids))!=len(ids) or set(ids)&set(reference['fit_campaign_ids']):raise ValueError('overlapping fit/calibration observables')
    values=[scores(c,reference)[1] for c in clean_campaigns]
    maxima=[float(np.median(x,axis=0).max()) for x in values]
    threshold=max(maxima);coactivity=[]
    for x in values:
        active=x>threshold
        coactivity.append(max(float(np.mean(active[:,i]&active[:,j])) for i,j in combinations(range(15),2)))
    return dict(profile=PROFILE,reference_digest=digest(reference),calibration_campaign_ids=ids,
        persistent_score_threshold=threshold,clean_campaign_persistent_maxima=maxima,
        pair_coactivity_threshold=max(.3,max(coactivity)),clean_campaign_coactivity_maxima=coactivity,
        labels_used=False,scope='Empirical clean maxima with a fixed .3 coactivity floor; no population false-positive guarantee.')


def detect(frames,reference,calibration):
    if calibration.get('profile')!=PROFILE or calibration.get('labels_used') is not False or calibration.get('reference_digest')!=digest(reference):
        raise ValueError('changed or label-informed calibration')
    if campaign_id(frames) in set(reference['fit_campaign_ids'])|set(calibration['calibration_campaign_ids']):
        raise ValueError('evaluation overlaps fit/calibration')
    threshold=calibration['persistent_score_threshold'];co=calibration['pair_coactivity_threshold']
    if not np.isfinite(threshold) or threshold<0 or not .3<=co<=1:raise ValueError('invalid threshold')
    clients,x=scores(frames,reference);persistent=np.median(x,axis=0);active=x>threshold
    anomalous=[c for c,v in zip(clients,persistent,strict=True) if v>threshold]
    edges=[];pairs=[]
    for i,j in combinations(range(15),2):
        fraction=float(np.mean(active[:,i]&active[:,j]))
        candidate=clients[i] in anomalous and clients[j] in anomalous and fraction>co
        pairs.append(dict(clients=[clients[i],clients[j]],coactive_fraction=fraction,candidate=candidate))
        if candidate:edges.append([clients[i],clients[j]])
    groups=_maximal_cliques(clients,edges)
    score_by=dict(zip(clients,persistent.tolist(),strict=True))
    feasible=sorted([g for g in groups if 15-len(g)>=10],key=lambda g:(-len(g),-min(score_by[c] for c in g),tuple(g)))
    return dict(profile=PROFILE,individual_anomalies=anomalous,persistent_scores=score_by,
        round_scores=x.tolist(),pair_coactivity=pairs,candidate_groups=groups,selected_group=feasible[0] if feasible else [],
        descriptive_tensor_pairs=pair_descriptors(frames),labels_used=False,
        automatic_exclusion_authorized=False,intentional_collusion_proved=False,
        interpretation='Concurrent persistent individual anomalies are investigative group hypotheses. Tensor similarity is reported separately, not required to become large. Shared benign causes remain possible.')
