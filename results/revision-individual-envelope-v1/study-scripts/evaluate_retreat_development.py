"""Second development hypothesis: individual clean envelopes and evidence retreat."""
from pathlib import Path
import json
import numpy as np
from fl_forensics.residual_geometry import load_geometry
from revision_dba_experiment import save

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-geometry-detector-v1'
save(lab/'retreat-development-protocol-before-scoring.json',{
    'profile':'client-envelope-retreat-development-v1','peak_retention_fraction':.5,
    'rule':'Both current risks exceed the individual clean envelope. Track minimum positive view excess and its peak during this uninterrupted high episode. If current excess falls below half of that peak, evidence is receding and cannot quarantine. Require two consecutive non-receding high rounds. Reset peak and confirmation on unsupported/non-high observations. No cumulative score authorizes action.',
    'candidate_order':['baseline','client-retreat','baseline-or-client-retreat'],
    'selection':'Zero never-attacker/currently-clean scheduled-attacker proposals and zero quorum loss over all 48 old cases, then maximum TP on shadow cases, then candidate order. No prospective case has been generated.'})
names=['baseline','client-retreat','baseline-or-client-retreat'];rows=[]
for rootname in ('revision-sequential-round-policy-v1','revision-current-evidence-policy-v1'):
    root=repo/'artifacts'/rootname
    for task in json.loads((root/'reserved-execution-before-training.json').read_bytes())['tasks']:
        cohort=task['cohort'];ref=load_geometry(lab/'development-models'/cohort/'geometry.npz')
        cal=json.loads((repo/'artifacts/revision-sequential-round-policy-v1/policy-calibration'/f'{cohort}.json').read_bytes())
        peak=np.zeros(15);previous=np.zeros(15,dtype=bool);previous_b=previous.copy()
        counts={n:{'tp':0,'never':0,'clean_scheduled':0,'quorum':0} for n in names}
        for number in range(1,16):
            response=json.loads((root/'private-episodes'/task['stream']/'rounds'/f'round-{number:03d}'/'worker-response.json').read_bytes())
            score=response['scored'];risk=np.stack([score['risk'][v][0] for v in ('conditioned','state-disabled')],axis=1)
            supported=all(score['state_distances'][v][0]<=ref['state_support_limits'][v]*(1+1e-12)+1e-12 for v in ('conditioned','state-disabled'))
            if not supported:peak[:]=0;previous[:]=False;previous_b[:]=False;continue
            excess=(risk-ref['tensor_risk_limits']).min(axis=1);high=excess>0
            peak=np.where(high,np.maximum(peak,excess),0.);non_receding=high&(excess>=.5*peak)
            selected=non_receding&previous
            z=np.maximum(0.,(risk-np.asarray(cal['centers']))/np.asarray(cal['scales']))
            bh=(z>np.asarray(cal['instantaneous_limits'])).all(axis=1);base=bh&previous_b
            active=set(task['attackers']) if task['mode']=='distributed' and number in task['attack_rounds'] else set()
            intended=set(task['attackers']) if task['mode']=='distributed' else set()
            for name,mask in [('baseline',base),('client-retreat',selected),('baseline-or-client-retreat',base|selected)]:
                chosen={c for c,yes in zip(cal['clients'],mask,strict=True) if yes};m=counts[name]
                m['tp']+=len(chosen&active);m['never']+=len(chosen-intended);m['clean_scheduled']+=len((chosen&intended)-active)
                m['quorum']+=int(15-len(chosen)<8)
            previous=non_receding.copy();previous_b=bh.copy()
        rows.append({'source':rootname,'task':task,'methods':counts})
totals={n:{k:sum(r['methods'][n][k] for r in rows) for k in ('tp','never','clean_scheduled','quorum')} for n in names}
for n in names:totals[n]['shadow_tp']=sum(r['methods'][n]['tp'] for r in rows if r['task']['branch']=='shadow-FedAvg')
eligible=[n for n in names if all(totals[n][k]==0 for k in ('never','clean_scheduled','quorum'))]
selected=max(eligible,key=lambda n:(totals[n]['shadow_tp'],-names.index(n)))
result={'profile':'retreat-development-comparison-v1','totals':totals,'cases':rows,'selected':selected,'eligible':eligible,
    'qualification':'Second explicit development hypothesis after the geometry-only head failed. No new reserved observations, attack labels or raw rows enter fitting. Halving is fixed, not a searched grid.'}
save(lab/'retreat-development-comparison.json',result);(out/'retreat-development-comparison.json').write_bytes((lab/'retreat-development-comparison.json').read_bytes())
print(json.dumps({'totals':totals,'selected':selected,'eligible':eligible}),flush=True)
