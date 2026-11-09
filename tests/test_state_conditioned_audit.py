import copy
import numpy as np
import pytest
from fl_forensics.state_conditioned_audit import (fit_state_reference,calibrate_state_threshold,
    detect_state_anomalies,residual_scores,save_model,load_model)
from fl_forensics.state_conditioned_fusion import calibrate_dual_view,detect_dual_view


def fixtures():
    rng=np.random.default_rng(8);bias=rng.normal(size=(5,20));slope=np.linspace(-1,0,5)
    def make():
        x=rng.normal(size=(10,20))
        return {'states':x,'updates':bias[None,:,:]+slope[None,:,None]*x[:,None,:]+rng.normal(scale=.01,size=(10,5,20)),
            'clients':list('abcde'),'sizes':[10,10],'cohort_id':'toy-fixed-client-data'}
    fit=[make() for _ in range(3)];cal=[make() for _ in range(3)];test=make()
    models={key:fit_state_reference(fit,condition_on_state=flag) for key,flag in [('conditioned',True),('state-disabled',False)]}
    calibrations={key:calibrate_state_threshold(cal,model) for key,model in models.items()}
    return fit,cal,test,models,calibrations


def test_state_response_is_explained_instead_of_accusing_clean_clients():
    fit,cal,test,models,cals=fixtures()
    assert residual_scores(test,models['conditioned'])['risk'].mean()<residual_scores(test,models['state-disabled'])['risk'].mean()
    assert detect_state_anomalies(test,models['conditioned'],cals['conditioned'])['flagged_clients']==[]


def test_local_departures_are_detected_despite_a_shared_starting_checkpoint():
    _,cal,test,models,cals=fixtures();test['updates'][:,:2,:]+=3
    joint=calibrate_dual_view(cal,models,cals)
    result=detect_dual_view(test,models,cals,joint)
    assert result['flagged_clients']==['a','b']
    assert not result['intentional_collusion_proved']


def test_unsupported_global_state_abstains_without_labeling_clients():
    _,_,test,models,cals=fixtures();test['states']+=1e8
    result=detect_state_anomalies(test,models['conditioned'],cals['conditioned'])
    assert result['status']=='abstained' and result['flagged_clients']==[]


def test_partial_reuse_of_fit_frames_is_rejected():
    fit,cal,_,models,_=fixtures();cal[0]['states'][0]=fit[0]['states'][0];cal[0]['updates'][0]=fit[0]['updates'][0]
    with pytest.raises(ValueError,match='overlap'):calibrate_state_threshold(cal,models['conditioned'])


def test_evaluation_cannot_reuse_calibration_frames():
    _,cal,_,models,cals=fixtures()
    with pytest.raises(ValueError,match='reuses'):detect_state_anomalies(cal[0],models['conditioned'],cals['conditioned'])


@pytest.mark.parametrize('field,value',[('attack_plan',{}),('rows',[]),('includes_raw_client_rows',True),('includes_attack_labels',True)])
def test_private_data_and_truth_are_rejected(field,value):
    _,_,test,models,cals=fixtures();test[field]=value
    with pytest.raises(ValueError):detect_state_anomalies(test,models['conditioned'],cals['conditioned'])


def test_cohort_change_requires_another_clean_reference():
    _,_,test,models,cals=fixtures();test['cohort_id']='changed-client-data'
    with pytest.raises(ValueError,match='schema'):detect_state_anomalies(test,models['conditioned'],cals['conditioned'])


def test_partial_horizon_cannot_report_a_complete_campaign_result():
    _,_,test,models,cals=fixtures();test['states']=test['states'][:5];test['updates']=test['updates'][:5]
    with pytest.raises(ValueError,match='horizon'):detect_state_anomalies(test,models['conditioned'],cals['conditioned'])


def test_nonfinite_updates_fail_closed():
    _,_,test,models,cals=fixtures();test['updates'][0,0,0]=np.nan
    with pytest.raises(ValueError,match='nonfinite'):detect_state_anomalies(test,models['conditioned'],cals['conditioned'])


def test_model_serialization_preserves_the_predictions(tmp_path):
    _,_,test,models,cals=fixtures();path=tmp_path/'model.npz';save_model(path,models['conditioned'])
    assert detect_state_anomalies(test,load_model(path),cals['conditioned'])==detect_state_anomalies(test,models['conditioned'],cals['conditioned'])


def test_view_roles_cannot_be_replaced_by_two_identical_models():
    _,cal,_,models,cals=fixtures();models['state-disabled']=models['conditioned']
    with pytest.raises(ValueError,match='roles'):calibrate_dual_view(cal,models,cals)


def test_duplicate_joint_calibration_is_rejected():
    _,cal,_,models,cals=fixtures()
    with pytest.raises(ValueError,match='duplicate'):calibrate_dual_view([cal[0],cal[0]],models,cals)


def test_calibration_payload_changes_are_detected():
    _,cal,test,models,cals=fixtures();joint=calibrate_dual_view(cal,models,cals)
    cals['conditioned']['threshold']+=1
    with pytest.raises(ValueError,match='changed'):detect_dual_view(test,models,cals,joint)


def test_invalid_score_normalization_is_rejected():
    _,_,test,models,cals=fixtures();cals['conditioned']['scales'][0]=0
    with pytest.raises(ValueError,match='normalization'):detect_state_anomalies(test,models['conditioned'],cals['conditioned'])
