import copy
import pytest
from test_retrospective_groups import campaign
from fl_forensics.group_calibration_v2 import (fit_group_reference,calibrate_group_threshold,
    detect_conditioned_groups,_scored_pairs,_maximal_cliques)
from fl_forensics.canonical import digest_object


def reference():
    return fit_group_reference([campaign(1),campaign(2),campaign(3)])


def test_fit_and_calibration_cannot_share_a_campaign():
    with pytest.raises(ValueError,match='overlap'):
        calibrate_group_threshold([campaign(1),campaign(5)],reference())


def test_evaluation_cannot_reuse_fit_or_calibration_data():
    ref=reference(); cal=calibrate_group_threshold([campaign(5),campaign(6)],ref)
    for seed in (1,5):
        with pytest.raises(ValueError,match='overlap'):
            detect_conditioned_groups(campaign(seed),ref,cal)


def test_persistent_clean_pair_similarity_is_conditioned_out():
    def same(seed):
        records=campaign(seed)
        for r in records:
            r['deltas'][1]=copy.deepcopy(r['deltas'][0])
            r['indicators'][1]={**r['indicators'][0],'client_id':'b'}
        return records
    ref=fit_group_reference([same(1),same(2),same(3)])
    pair=next(p for p in _scored_pairs(same(4),ref) if p['clients']==['a','b'])
    assert pair['conditioned_score'] < 1e-10


def test_chain_edges_do_not_accuse_the_entire_connected_component():
    assert _maximal_cliques(['a','b','c'],[['a','b'],['b','c']])==[['a','b'],['b','c']]


def test_temporal_increase_is_not_blocked_by_an_impossible_raw_correlation_threshold():
    ref=reference()
    # A valid bounded channel can have a standardized score above one.
    for channels in ref['references'].values():
        for channel in channels.values(): channel.update(center=-1.,scale=.05)
    pairs=_scored_pairs(campaign(20),ref)
    assert max(p['conditioned_score'] for p in pairs if p['conditioned_score'] is not None)>1


def test_modified_reference_or_label_informed_calibration_is_rejected():
    ref=reference(); cal=calibrate_group_threshold([campaign(5),campaign(6)],ref)
    cal['labels_used']=True
    with pytest.raises(ValueError): detect_conditioned_groups(campaign(20),ref,cal)


def test_new_client_population_requires_new_calibration():
    ref=reference(); cal=calibrate_group_threshold([campaign(5),campaign(6)],ref)
    changed=campaign(20)
    for record in changed:
        record['client_ids'][-1]='new'
        record['indicators'][-1]['client_id']='new'
    with pytest.raises(ValueError,match='population'):
        detect_conditioned_groups(changed,ref,cal)
