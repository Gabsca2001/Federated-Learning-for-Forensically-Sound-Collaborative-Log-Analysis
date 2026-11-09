"""Clean-calibrated connected candidate sets, without an all-pairs clique claim.

Pairs and triples are separate calibrated families. A triple's score is the
mean of its two strongest pair edges, the weight of its maximum spanning tree
divided by two. This is an investigation hypothesis, never proof of collusion.
"""
from itertools import combinations
import math

import numpy as np

from .group_calibration_v2 import _identity, _pairs, _scored_pairs

PROFILE = 'tree-connected-campaign-calibration-v3'


def candidate_scores(pairs):
    edges = {tuple(sorted(p['clients'])): p['conditioned_score'] for p in pairs}
    clients = sorted({c for edge in edges for c in edge})
    result = []
    for size in (2, 3):
        for group in combinations(clients, size):
            values = [(edges.get(edge), edge) for edge in combinations(group, 2)]
            defined = sorted([(float(v), edge) for v, edge in values if v is not None], reverse=True)
            if len(defined) < size-1:
                continue
            selected = defined[:size-1]
            if any(not math.isfinite(v) or v < 0 for v, _ in selected):
                raise ValueError('invalid conditioned pair score')
            # For a triple any two distinct edges form a connected spanning tree.
            result.append({'clients':list(group),'size':size,
                           'score':sum(v for v, _ in selected)/(size-1),
                           'witness_edges':[list(edge) for _, edge in selected]})
    return result


def calibrate_tree_groups(clean_campaigns, reference):
    if len(clean_campaigns) < 3:
        raise ValueError('at least three disjoint clean calibration campaigns required')
    maxima = {2:[],3:[]}
    identities = []
    for rounds in clean_campaigns:
        identity = _identity(_pairs(rounds))
        if identity in reference['fit_campaign_ids'] or identity in identities:
            raise ValueError('fit/calibration overlap or duplicate campaign')
        identities.append(identity)
        groups = candidate_scores(_scored_pairs(rounds,reference))
        for size in maxima:
            values = [g['score'] for g in groups if g['size']==size]
            if not values:
                raise ValueError('undefined clean group family')
            maxima[size].append(max(values))
    return {'profile':PROFILE,'reference_digest':_identity(reference),
            'calibration_campaign_ids':identities,'labels_used':False,
            'families':{str(size):{'campaign_maxima':values,'threshold':max(values)}
                        for size, values in maxima.items()},
            'ranking':'Triples before pairs, then score/threshold, then client tuple; investigative recall preference, not a posterior probability.',
            'scope':'Empirical maxima per family. Three clean histories do not establish a population false-positive guarantee.'}


def detect_tree_groups(rounds,reference,calibration,*,minimum_survivors=8):
    if (calibration.get('profile') != PROFILE or calibration.get('labels_used') is not False
            or calibration.get('reference_digest') != _identity(reference)):
        raise ValueError('calibration/reference binding changed')
    identity = _identity(_pairs(rounds))
    if identity in set(reference['fit_campaign_ids']) | set(calibration['calibration_campaign_ids']):
        raise ValueError('evaluation overlaps fitting/calibration')
    clients = rounds[0]['client_ids']
    if type(minimum_survivors) is not int or not 1 <= minimum_survivors <= len(clients):
        raise ValueError('invalid survivor quorum')
    groups = candidate_scores(_scored_pairs(rounds,reference))
    for group in groups:
        threshold = calibration['families'][str(group['size'])]['threshold']
        if not math.isfinite(threshold) or threshold < 0:
            raise ValueError('invalid clean threshold')
        group['threshold'] = threshold
        group['candidate'] = group['score'] > threshold
        group['ratio'] = group['score']/max(threshold,.05)
    candidates = sorted([g for g in groups if g['candidate']],
                        key=lambda g:(-g['size'],-g['ratio'],tuple(g['clients'])))
    feasible = [g for g in candidates if len(clients)-g['size'] >= minimum_survivors]
    return {'profile':PROFILE,'groups':groups,'candidate_groups':candidates,
            'selected_group':feasible[0]['clients'] if feasible else [],
            'labels_used':False,'automatic_quarantine_authorized':False,
            'intentional_collusion_proved':False,
            'interpretation':'Connected anomalous candidate set; a weak/missing third pair is not asserted to be a strong edge.'}
