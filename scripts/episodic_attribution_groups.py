"""V5: separate utility risk from repeated magnitude anomalies.

Group edges require the same repeated anomaly mechanism. Neither concurrence
nor a large vector proves malicious intent. This is an offline research adapter.
"""
from itertools import combinations
import numpy as np
import retrospective_anomaly_groups as v4
from coherent_gradient_protocol import digest
from fl_forensics.group_calibration_v2 import _maximal_cliques

PROFILE='separated-utility-magnitude-episodes-v5'
MINIMUM_EXCESS_ROUNDS=3
fit_reference=v4.fit_reference


def channel_scores(frames,reference):
    # Validate the frozen feature/reference contract through the original rule.
    v4.scores(frames,reference)
    clients,x=v4.observations(frames);out=[]
    for k,name in enumerate(v4.FEATURES):
        channel=reference['channels'][name]
        out.append(np.maximum(0.,(x[:,:,k]-channel['center'])/channel['scale']))
    return clients,out[0],out[1]


def calibrate(clean_campaigns,reference):
    comparison=v4.calibrate(clean_campaigns,reference)
    identities=[v4.campaign_id(c) for c in clean_campaigns]
    values=[channel_scores(c,reference)[1] for c in clean_campaigns]
    maxima=[float(np.sort(x,axis=0)[-MINIMUM_EXCESS_ROUNDS].max()) for x in values]
    threshold=max(maxima);coactivity=[]
    for x in values:
        active=x>threshold
        coactivity.append(max(int(np.count_nonzero(active[:,i]&active[:,j])) for i,j in combinations(range(15),2)))
    return dict(profile=PROFILE,reference_digest=digest(reference),calibration_campaign_ids=identities,
        minimum_excess_rounds=MINIMUM_EXCESS_ROUNDS,episode_score_threshold=threshold,
        clean_campaign_episode_maxima=maxima,coactive_round_count_threshold=max(MINIMUM_EXCESS_ROUNDS-1,max(coactivity)),
        clean_campaign_coactivity_maxima=coactivity,utility_score_threshold=comparison['persistent_score_threshold'],
        v4_comparison_calibration=comparison,labels_used=False,
        scope='Third-largest norm-channel score calibrated by clean campaign maxima. Fixed ten-round horizon, no window or threshold search. Empirical calibration only.')


def detect(frames,reference,calibration):
    if (calibration.get('profile')!=PROFILE or calibration.get('labels_used') is not False
            or calibration.get('reference_digest')!=digest(reference)
            or calibration.get('minimum_excess_rounds')!=MINIMUM_EXCESS_ROUNDS):
        raise ValueError('changed or label-informed episode calibration')
    if v4.campaign_id(frames) in set(reference['fit_campaign_ids'])|set(calibration['calibration_campaign_ids']):
        raise ValueError('evaluation overlaps fitting/calibration')
    threshold=calibration['episode_score_threshold'];support=calibration['coactive_round_count_threshold']
    if not np.isfinite(threshold) or threshold<0 or type(support) is not int or not 2<=support<=10:
        raise ValueError('invalid episode/coactivity threshold')
    clients,norm,validation=channel_scores(frames,reference)
    episode=np.sort(norm,axis=0)[-MINIMUM_EXCESS_ROUNDS];active=norm>threshold
    individual=[c for c,s in zip(clients,episode,strict=True) if s>threshold]
    pairs=[];edges=[]
    for i,j in combinations(range(15),2):
        rounds=[t+1 for t in range(10) if active[t,i] and active[t,j]]
        candidate=clients[i] in individual and clients[j] in individual and len(rounds)>support
        pair=dict(clients=[clients[i],clients[j]],shared_mechanism='repeated_magnitude_excess',coexceedance_rounds=rounds,candidate=candidate)
        pairs.append(pair)
        if candidate:edges.append(pair['clients'])
    groups=_maximal_cliques(clients,edges);by_client=dict(zip(clients,episode.tolist(),strict=True))
    feasible=sorted([g for g in groups if 15-len(g)>=10],key=lambda g:(-len(g),-min(by_client[c] for c in g),tuple(g)))
    comparison=v4.detect(frames,reference,calibration['v4_comparison_calibration'])
    utility=np.median(validation,axis=0);utility_threshold=calibration['utility_score_threshold']
    if not np.isfinite(utility_threshold) or utility_threshold<0:raise ValueError('invalid utility threshold')
    return dict(profile=PROFILE,individual_anomalies=individual,episode_scores=by_client,
        magnitude_round_scores=norm.tolist(),magnitude_excess_rounds={c:[t+1 for t in range(10) if active[t,i]] for i,c in enumerate(clients)},
        candidate_groups=groups,selected_group=feasible[0] if feasible else [],pair_evidence=pairs,
        utility_risk_clients=[c for c,s in zip(clients,utility,strict=True) if s>utility_threshold],
        utility_persistent_scores=dict(zip(clients,utility.tolist(),strict=True)),utility_round_scores=validation.tolist(),
        utility_scope='Macro-F1 contribution risk remains visible but cannot create actor anomalies or group edges.',
        descriptive_tensor_pairs=comparison['descriptive_tensor_pairs'],v4_comparison=comparison,
        labels_used=False,automatic_exclusion_authorized=False,intentional_collusion_proved=False,
        interpretation='Investigative group sharing repeated magnitude excess in at least three common rounds. Legitimate large updates can also qualify. Sub-threshold, staggered or fewer-than-three episodes may be missed.')
