"""Document an input-level limitation, without claiming a realized DBA attack."""
from pathlib import Path
import json
from fl_forensics.client_envelope_policy import ClientEnvelopePolicy
from revision_dba_experiment import save

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-geometry-detector-v1'
cal={'profile':'sequential-round-decision-v1','cohort_id':'toy','clients':list('abc'),'horizon':15,'drift':.5,'minimum_consecutive':2,
    'centers':[[0,0]]*3,'scales':[[1,1]]*3,'instantaneous_limits':[10,10],'cumulative_limits':[30,30],
    'review_instantaneous_limits':[1,1],'review_cumulative_limits':[2,2]}
envelope={'profile':'clean-client-risk-envelope-v1','cohort_id':'toy','clients':list('abc'),
    'tensor_risk_limits':[[2,2]]*3,'retained_peak_fraction':.5}
p=ClientEnvelopePolicy(cal,envelope,minimum_contributors=2);decisions=[]
for t in range(1,16):
    risk=2.4 if t==1 else 2.1
    d=p.step(t,{v:[risk,0,0] for v in ('conditioned','state-disabled')},context_supported=True,
        mandatory_gate=dict.fromkeys('abc',True),masses=dict.fromkeys('abc',1),
        expected_previous_digest=p.head,source_observation_sha256=f'{t:064x}')
    assert not d['quarantine_current_round'] and d['clients']['a']['client_envelope_current_high']
    assert d['clients']['a']['action']=='review_required'
    decisions.append({'round':t,'raw_risk':risk,'action':d['clients']['a']['action'],
        'current_excess':d['clients']['a']['client_envelope_current_minimum_excess'],
        'episode_peak':d['clients']['a']['client_envelope_episode_peak_excess']})
result={'profile':'peak-retention-input-limitation-audit-v1','decisions':decisions,
    'finding':'A moderate initial excess .4 followed by sustained excess .1 leaves the individual channel review-only for all remaining rounds while the baseline also stays below its global limit. The unchanged episode peak has no timeout.',
    'actual_model_update_attack_demonstrated':False,'prospective_method_or_threshold_changed':False,
    'qualification':'Synthetic risk-sequence counterexample to a possible stronger liveness claim. It does not establish that a client can realize this exact trajectory in the fixed model. It demonstrates why finite pilot success cannot certify adaptive attack resistance or guaranteed eventual quarantine.'}
save(lab/'peak-suppression-audit.json',result);(out/'peak-suppression-audit.json').write_bytes((lab/'peak-suppression-audit.json').read_bytes())
print(json.dumps({k:v for k,v in result.items() if k!='decisions'}))
