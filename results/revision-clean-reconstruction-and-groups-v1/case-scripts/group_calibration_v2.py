"""Pair-conditioned clean references and campaign-level threshold calibration.

This is a retrospective candidate generator, not proof of malicious intent.
Fit, calibration and evaluation campaigns must be disjoint.
"""
from __future__ import annotations

from itertools import combinations
import math

import numpy as np

from fl_forensics.canonical import sha256_bytes
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.retrospective_groups import FEATURES, pair_descriptors

PROFILE = 'pair-conditioned-campaign-calibration-v2'


def _pairs(rounds):
    return pair_descriptors(rounds)


def _identity(pairs):
    return sha256_bytes(derived_json_bytes(pairs))


def fit_group_reference(clean_campaigns):
    if len(clean_campaigns) < 2:
        raise ValueError('at least two clean reference campaigns are required')
    all_pairs = [_pairs(c) for c in clean_campaigns]
    identities = [_identity(p) for p in all_pairs]
    if len(set(identities)) != len(identities):
        raise ValueError('duplicate reference campaign')
    keys = [tuple(p['clients']) for p in all_pairs[0]]
    if any([tuple(p['clients']) for p in pairs] != keys for pairs in all_pairs):
        raise ValueError('reference client populations differ')
    reference = {}
    for index,key in enumerate(keys):
        channels = {}
        for feature in FEATURES:
            values = [pairs[index][feature] for pairs in all_pairs if pairs[index][feature] is not None]
            if len(values) < 2:
                continue
            center = float(np.median(values))
            scale = max(0.05, 1.4826 * float(np.median(np.abs(np.asarray(values)-center))))
            channels[feature] = {'center':center,'scale':scale}
        reference[','.join(key)] = channels
    return {'profile':PROFILE,'fit_campaign_ids':identities,'features':list(FEATURES),
        'scale_floor':0.05,'references':reference,'labels_used':False,
        'score_definition':'Maximum positive standardized increase over the same pair clean reference; scale=max(0.05,1.4826*MAD). No strict threshold above a bounded raw similarity.'}


def _scored_pairs(rounds, reference):
    if reference.get('profile') != PROFILE or reference.get('labels_used') is not False or reference.get('features') != list(FEATURES):
        raise ValueError('unknown or label-informed reference')
    pairs = _pairs(rounds)
    if {','.join(p['clients']) for p in pairs} != set(reference['references']):
        raise ValueError('candidate client population differs from the reference')
    for pair in pairs:
        channels = reference['references'][','.join(pair['clients'])]
        scores = {}
        for feature, channel in channels.items():
            center, scale = channel['center'], channel['scale']
            if not math.isfinite(center) or not math.isfinite(scale) or scale < 0.05:
                raise ValueError('invalid clean reference channel')
            if pair[feature] is not None:
                scores[feature] = max(0., (pair[feature]-center)/scale)
        pair['positive_standardized_increases'] = scores
        pair['conditioned_score'] = max(scores.values()) if scores else None
    return pairs


def calibrate_group_threshold(clean_campaigns, reference):
    if len(clean_campaigns) < 2:
        raise ValueError('at least two disjoint clean calibration campaigns are required')
    maxima, identities = [], []
    for campaign in clean_campaigns:
        raw = _pairs(campaign)
        identity = _identity(raw)
        if identity in reference['fit_campaign_ids'] or identity in identities:
            raise ValueError('fit/calibration overlap or duplicate campaign')
        identities.append(identity)
        pairs = _scored_pairs(campaign,reference)
        scores = [p['conditioned_score'] for p in pairs if p['conditioned_score'] is not None]
        if not scores:
            raise ValueError('calibration campaign has no defined pair scores')
        maxima.append(max(scores))
    return {'profile':PROFILE,'reference_digest':_identity(reference),
        'calibration_campaign_ids':identities,'campaign_maxima':maxima,
        'threshold':max(maxima),'labels_used':False,
        'familywise_unit':'Maximum over all pairs and all three feature channels within one fixed-horizon campaign; empirical calibration only. Small campaign count does not establish a low false-positive rate.'}


def _maximal_cliques(clients, edges):
    adjacency={c:set() for c in clients}
    for a,b in edges:
        adjacency[a].add(b); adjacency[b].add(a)
    found=[]
    def visit(current, candidates, excluded):
        if not candidates and not excluded:
            if len(current)>=2:
                found.append(sorted(current))
            return
        for node in sorted(list(candidates)):
            visit(current|{node}, candidates&adjacency[node], excluded&adjacency[node])
            candidates.remove(node); excluded.add(node)
    visit(set(),set(clients),set())
    return sorted(found)


def detect_conditioned_groups(rounds,reference,calibration):
    if calibration.get('profile') != PROFILE or calibration.get('labels_used') is not False or calibration.get('reference_digest') != _identity(reference):
        raise ValueError('calibration does not bind this clean reference')
    threshold=calibration['threshold']
    if not math.isfinite(threshold) or threshold < 0:
        raise ValueError('invalid group score threshold')
    if _identity(_pairs(rounds)) in set(reference['fit_campaign_ids'])|set(calibration['calibration_campaign_ids']):
        raise ValueError('evaluation campaign overlaps fitting or calibration')
    pairs=_scored_pairs(rounds,reference)
    edges=[]
    for pair in pairs:
        pair['candidate_edge']=pair['conditioned_score'] is not None and pair['conditioned_score'] > threshold
        if pair['candidate_edge']:
            edges.append(pair['clients'])
    groups=_maximal_cliques(rounds[0]['client_ids'],edges)
    return {'profile':PROFILE,'candidate_groups':groups,'pairs':pairs,'threshold':threshold,
        'labels_used':False,'intentional_collusion_proved':False,
        'interpretation':'Pair-conditioned anomalous coordination hypotheses. Maximal cliques avoid merging clients connected only through a chain. Similar data or benign distribution changes can still explain candidates.'}
