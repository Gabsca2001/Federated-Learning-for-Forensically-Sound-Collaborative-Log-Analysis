import copy
from fractions import Fraction

import numpy as np
import pytest

from fl_forensics.group_calibration_v3 import candidate_scores,calibrate_tree_groups,detect_tree_groups
from fl_forensics.group_calibration_v2 import fit_group_reference
from fl_forensics.robust_bounded_aggregation import aggregate_robust_bounded,verify_robust_bounded
from test_retrospective_groups import campaign


def test_tree_witness_does_not_invent_the_weak_third_edge():
    pairs=[{'clients':['a','b'],'conditioned_score':9.},
           {'clients':['a','c'],'conditioned_score':1.},
           {'clients':['b','c'],'conditioned_score':7.}]
    triple=next(g for g in candidate_scores(pairs) if g['size']==3)
    assert triple['score']==8.
    assert ['a','c'] not in triple['witness_edges']


def test_tree_selection_has_fit_calibration_and_evaluation_separation():
    ref=fit_group_reference([campaign(1),campaign(2),campaign(3)])
    cal=calibrate_tree_groups([campaign(4),campaign(5),campaign(6)],ref)
    for seed in (1,4):
        with pytest.raises(ValueError,match='overlap'):
            detect_tree_groups(campaign(seed),ref,cal,minimum_survivors=1)
    changed=copy.deepcopy(cal);changed['labels_used']=True
    with pytest.raises(ValueError):
        detect_tree_groups(campaign(7),ref,changed,minimum_survivors=1)


def args():
    return dict(masses={'a':1,'b':1,'c':1},mandatory_gates={'a':True,'b':True,'c':True},
                limits=[100.],reference_digest='a'*64,minimum_contributors=2)


def test_geometric_median_limits_an_outlier_without_calling_it_malicious():
    base=[np.array([0.])]
    updates={c:[np.array([x])] for c,x in [('a',1.),('b',1.1),('c',90.)]}
    result,report=aggregate_robust_bounded(base,updates,**args())
    assert 1. <= result[0][0] < 1.2
    assert abs(sum(Fraction(w) for w in report['final_coefficients'].values())-1)==0
    verify_robust_bounded(base,updates,report,**args())
    altered=copy.deepcopy(report);altered['converged']=not altered['converged']
    with pytest.raises(ValueError,match='reconstruct'):
        verify_robust_bounded(base,updates,altered,**args())


def test_gate_veto_and_no_quorum_are_preserved():
    base=[np.array([0.])];updates={c:[np.array([1.])] for c in 'abc'}
    kw=args();kw['mandatory_gates']={'a':True,'b':False,'c':False}
    result,report=aggregate_robust_bounded(base,updates,**kw)
    assert result is None and not report['quorum_satisfied']


def test_final_convex_combination_keeps_tensor_cap_and_input_identity():
    base=[np.zeros(3)]
    updates={'a':[np.array([90.,0.,0.])],'b':[np.array([0.,90.,0.])],'c':[np.array([0.,0.,90.])]}
    originals=copy.deepcopy(updates)
    kw=args();kw['limits']=[2.]
    result,report=aggregate_robust_bounded(base,updates,**kw)
    assert np.linalg.norm(result[0])<=2.+1e-12
    assert all(np.array_equal(updates[c][0],originals[c][0]) for c in updates)
    assert all(float(Fraction(w))>=0 for w in report['final_coefficients'].values())
