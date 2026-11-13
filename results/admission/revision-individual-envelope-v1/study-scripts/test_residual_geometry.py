import copy
import numpy as np
import pytest
from fl_forensics.residual_geometry import (parameter_groups,fit_geometry,geometry_scores,save_geometry,load_geometry)
from fl_forensics.state_conditioned_audit import fit_state_reference,residual_scores


def fixture():
    rng=np.random.default_rng(301);bias=rng.normal(size=(5,20))
    def make():
        x=rng.normal(scale=.2,size=(8,20))
        return {'states':x,'updates':bias[None,:,:]-.1*x[:,None,:]+rng.normal(scale=.03,size=(8,5,20)),
            'clients':list('abcde'),'sizes':[16,4],'cohort_id':'toy'}
    fitting=[make(),make(),make()];normalizer=[make(),make()];nulls=[make(),make()]
    models={v:fit_state_reference(fitting,condition_on_state=flag) for v,flag in [('conditioned',True),('state-disabled',False)]}
    ref=fit_geometry(normalizer,nulls,models,[[4,4],[4]])
    return normalizer,nulls,models,ref,make()


def test_groups_cover_all_rows_columns_and_bias_without_attack_indices():
    groups=parameter_groups([[3,4],[2]])
    counts=np.bincount([i for g in groups for i in g['indices']],minlength=14)
    assert counts.tolist()==[2]*12+[1]*2
    assert len(groups)==8


def test_preserved_tensor_channel_matches_existing_predictor():
    _,_,models,ref,o=fixture();scores=geometry_scores(o,models,ref)
    for j,v in enumerate(('conditioned','state-disabled')):
        assert np.allclose(scores['tensor_risk'][:,:,j],residual_scores(o,models[v])['risk'],rtol=0,atol=1e-14)


def test_localized_departure_has_identifiable_current_parameter_groups():
    _,_,models,ref,o=fixture();o['updates'][:,0,[1,5,9,13]]+=20
    result=geometry_scores(o,models,ref)
    ids=[g['id'] for g,high in zip(ref['groups'],(result['group_excess'][:,0]>0).all(axis=0),strict=True) if high]
    assert 'tensor-0-axis-1-1' in ids


def test_normalizer_null_overlap_is_rejected():
    n,_,m,_,_=fixture()
    with pytest.raises(ValueError,match='overlap'):fit_geometry(n,n,m,[[4,4],[4]])


def test_wrong_public_tensor_shapes_are_rejected():
    n,c,m,_,_=fixture()
    with pytest.raises(ValueError,match='schema'):fit_geometry(n,c,m,[[5,4],[4]])


@pytest.mark.parametrize('field,value',[('attack_plan',{}),('rows',[]),('includes_attack_labels',True),('includes_raw_client_rows',True)])
def test_private_rows_and_truth_are_not_observable_inputs(field,value):
    _,_,m,r,o=fixture();o[field]=value
    with pytest.raises(ValueError):geometry_scores(o,m,r)


def test_future_frames_do_not_change_an_existing_score_prefix():
    _,_,m,r,o=fixture();prefix={**o,'states':o['states'][:3],'updates':o['updates'][:3]}
    a=geometry_scores(prefix,m,r)['group_excess'];b=geometry_scores(o,m,r)['group_excess'][:3]
    assert np.allclose(a,b,rtol=0,atol=1e-12)
    assert np.array_equal(a>0,b>0)


def test_predictor_change_is_rejected():
    _,_,m,r,o=fixture();m['conditioned']['ymean'][0,0]+=1
    with pytest.raises(ValueError,match='changed'):geometry_scores(o,m,r)


def test_serialization_preserves_group_evidence(tmp_path):
    _,_,m,r,o=fixture();p=tmp_path/'geometry.npz';save_geometry(p,r)
    a=geometry_scores(o,m,r);b=geometry_scores(o,m,load_geometry(p))
    assert np.array_equal(a['group_excess'],b['group_excess']) and a['frame_ids']==b['frame_ids']


def test_unsupported_state_is_explicit():
    _,_,m,r,o=fixture();o['states']+=1e7
    assert not geometry_scores(o,m,r)['supported'].any()


def test_nonfinite_observations_fail_before_scoring():
    _,_,m,r,o=fixture();o['updates'][0,0,0]=np.nan
    with pytest.raises(ValueError,match='nonfinite'):geometry_scores(o,m,r)


def test_view_roles_cannot_be_replaced_with_copies():
    n,c,m,_,_=fixture();m['state-disabled']=m['conditioned']
    with pytest.raises(ValueError,match='roles'):fit_geometry(n,c,m,[[4,4],[4]])
