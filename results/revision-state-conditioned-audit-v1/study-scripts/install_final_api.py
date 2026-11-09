"""Preserve prototype sources; install the stricter public observation contract."""
from pathlib import Path

source=Path(__file__).parent
target=Path('src/fl_forensics')
t=(source/'state_conditioned_audit.py').read_text()
t=t.replace("frame_ids=[];risks=[];maxima=[]", "frame_ids=[];risks=[];maxima=[];horizons=[]")
t=t.replace("scored=residual_scores(observation,model)\n        if len", "scored=residual_scores(observation,model)\n        horizons.append(len(scored['risk']))\n        if len")
t=t.replace("risks=np.stack(risks)", "if len(set(horizons))!=1:raise ValueError('calibration horizons differ')\n    risks=np.stack(risks)")
t=t.replace("'risk_quantile':.8,'minimum_supported_frames':3,", "'risk_quantile':.8,'expected_horizon':horizons[0],'minimum_supported_frames':3,")
marker="    scored=residual_scores(observation,model)\n    if set(scored['frame_ids'])"
replacement="""    scored=residual_scores(observation,model)
    if calibration.get('risk_quantile')!=.8 or calibration.get('minimum_supported_frames')!=3 or calibration.get('calibration_scale_margin')!=1.:
        raise ValueError('changed scoring protocol')
    if len(scored['risk'])!=calibration.get('expected_horizon'):
        raise ValueError('the complete calibrated horizon is required')
    center=np.asarray(calibration['centers'],dtype=np.float64)
    scale=np.asarray(calibration['scales'],dtype=np.float64)
    if center.shape!=(len(model['schema']['clients']),) or scale.shape!=center.shape or not np.isfinite(center).all() or not np.isfinite(scale).all() or np.any(scale<.05):
        raise ValueError('invalid client score normalization')
    if set(scored['frame_ids'])"""
assert marker in t;t=t.replace(marker,replacement)
(target/'state_conditioned_audit.py').write_text(t)
t=(source/'state_conditioned_fusion.py').read_text().replace('from state_conditioned_audit import','from .state_conditioned_audit import')
t=t.replace("case_scores=[]", """if not models['conditioned']['condition_on_state'] or models['state-disabled']['condition_on_state']:
        raise ValueError('predictor view roles are incorrect')
    case_scores=[];seen=set()""")
t=t.replace("for observation in observations:\n        standardized=[]", """for observation in observations:
        frames=set(residual_scores(observation,models['conditioned'])['frame_ids'])
        if frames&seen:raise ValueError('duplicate joint calibration frames')
        seen.update(frames)
        standardized=[]""")
t=t.replace("'views':leaves,'automatic_exclusion_validated':False}", "'views':leaves,'automatic_exclusion_validated':False,'intentional_collusion_proved':False}")
(target/'state_conditioned_fusion.py').write_text(t)
print('Public API installed; prototype files remain preserved')
