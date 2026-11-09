"""Post-hoc coefficient-only feasibility study, not a new defense evaluation."""
from pathlib import Path
from fractions import Fraction as F
from itertools import combinations
import hashlib,json,csv,shutil
import numpy as np
from scipy.optimize import minimize,linprog
from scipy.special import xlogy

ROOT=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
LAB=ROOT/'artifacts/revision-capped-final-v1'
OUT=Path(__file__).parent/'exact-group-exploration'
OUT.mkdir(exist_ok=True)

def project(proposal):
    # This function never receives attacker labels or evaluation scores.
    ids=sorted(i for i,v in proposal.items() if v>0)
    q=len(ids); gamma=F(1,3); k=3
    if q<9: raise ValueError('Infeasible positive support')
    total=sum(proposal.values()); prior={i:proposal[i]/total for i in proposal}
    if sum(sorted(prior.values(),reverse=True)[:k])<=gamma:
        return prior,{'solver_success':True,'gap':0.,'repair':False}
    if q==9:
        return {i:F(1,q) if i in ids else F() for i in proposal},{'solver_success':True,'gap':0.,'repair':False}
    p=np.array([float(prior[i]) for i in ids]); p/=p.sum()
    A=np.zeros((len(list(combinations(range(q),k))),q))
    for row,indices in enumerate(combinations(range(q),k)): A[row,list(indices)]=1
    def fun(x): return float(np.sum(xlogy(x,x/p)))
    def jac(x): return np.log(np.maximum(x,1e-300)/p)+1
    # A fixed feasible uniform start. No tuning from attack labels or ASR.
    r=minimize(fun,np.full(q,1/q),jac=jac,method='SLSQP',bounds=[(1e-16,1)]*q,
        constraints=[{'type':'eq','fun':lambda x:x.sum()-1,'jac':lambda x:np.ones(q)},
                     {'type':'ineq','fun':lambda x:1/3-A@x,'jac':lambda x:-A}],
        options={'ftol':1e-11,'maxiter':300})
    assert np.isfinite(r.x).all() and r.x.min()>=0
    raw={i:F(float(v)) for i,v in zip(ids,r.x)}; s=sum(raw.values())
    beta={i:raw[i]/s if i in raw else F() for i in proposal}
    top=sum(sorted(beta.values(),reverse=True)[:k]); repair=top>gamma
    if repair:
        tau=(top-gamma)/(top-F(k,q))
        beta={i:(1-tau)*v+tau*F(1,q) if i in raw else F() for i,v in beta.items()}
    assert sum(beta.values())==1
    assert sum(sorted(beta.values(),reverse=True)[:k])<=gamma
    assert all(beta[i]==0 for i,v in proposal.items() if not v)
    b=np.array([float(beta[i]) for i in ids]); g=jac(b)
    lp=linprog(g,A_ub=A,b_ub=np.full(len(A),1/3),A_eq=np.ones((1,q)),b_eq=[1.],bounds=(0,None),method='highs')
    gap=max(0.,float(g@b-lp.fun)) if lp.success else None
    return beta,{'solver_success':bool(r.success),'gap':gap,'repair':repair}

# Analytic and support checks independent of the recorded campaign.
p={'dominant':F(7,10),**{str(i):F(3,140) for i in range(14)},'veto':F()}
b,info=project(p)
assert abs(float(b['dominant'])-2/9)<1e-6 and b['veto']==0
uniform={str(i):F(1,15) for i in range(15)}
assert project(uniform)[0]==uniform
assert set(project({str(i):F(1,9) for i in range(9)})[0].values())=={F(1,9)}
try: project({str(i):F(1,8) for i in range(8)})
except ValueError: pass
else: raise AssertionError('Infeasible roster accepted')

rows=[]; inputs=[]
protocol=json.loads((LAB/'protocol-before-training.json').read_text())
for task in protocol['tasks']:
    if task['method']!='capped_robust' or task['mode']=='clean':continue
    for number in range(1,16):
        path=LAB/'cases'/task['name']/'evidence/rounds'/f'round-{number:03d}'/'gate-state.json'
        state=json.loads(path.read_text())['selected_aggregation_derivation']
        p={i:F(v) for i,v in state['projection']['normalized_proposal'].items()}
        old={i:F(v) for i,v in state['beta'].items()}
        candidate,info=project(p)
        def kl(beta):return sum(float(v)*np.log(float(v/p[i])) for i,v in beta.items() if v)
        oldkl=kl(old); newkl=kl(candidate)
        # An inconclusive numeric optimum cannot be treated as a certified optimum.
        usable=bool(info['solver_success'] and info['gap'] is not None and info['gap']<1e-6 and newkl<=oldkl+1e-8)
        attackers=task['attackers']
        inputs.append({'case':task['name'],'round':number,'gate_state_sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        rows.append({'case':task['name'],'round':number,'active_round':number<=10,
            'numeric_candidate_qualified':usable,**info,'old_kl':oldkl,'candidate_kl':newkl,
            'proposal_attacker_share':float(sum(p[i] for i in attackers)),
            'old_attacker_share':float(sum(old[i] for i in attackers)),
            'candidate_attacker_share':float(sum(candidate[i] for i in attackers)),
            'candidate_coefficients':json.dumps({i:str(v) for i,v in candidate.items()},sort_keys=True)})
    print('Explored',task['name'],flush=True)
active=[r for r in rows if r['active_round']]
summary={'scope':'Post-hoc coefficient-only exploration on the recorded capped histories; no retraining, no test inference, no ASR counterfactual, no default change.',
    'rows':len(rows),'active_rows':len(active),'numeric_candidates_qualified':sum(r['numeric_candidate_qualified'] for r in rows),
    'old_active_share_increases':sum(r['old_attacker_share']>r['proposal_attacker_share']+1e-12 for r in active),
    'candidate_active_share_increases':sum(r['candidate_attacker_share']>r['proposal_attacker_share']+1e-12 for r in active),
    'candidate_active_share_lower_than_old':sum(r['candidate_attacker_share']<r['old_attacker_share']-1e-9 for r in active),
    'candidate_active_share_higher_than_old':sum(r['candidate_attacker_share']>r['old_attacker_share']+1e-9 for r in active),
    'analytic_dominant_example':{'prior':0.7,'old_individual_ceiling':1/9,'feasible_group_projection':float(b['dominant'])},
    'constraint':'sum of largest three coefficients <= 1/3, exact rational feasibility repair, zero support preserved',
    'optimality':'Numerical tangent-LP gap check, not an exact symbolic optimum certificate',
    'optimizer_uses_attacker_labels':False,'current_defense_validated':False}
with (OUT/'coefficients.csv').open('w',newline='') as h:
    w=csv.DictWriter(h,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
(OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
(OUT/'input-locks.json').write_text(json.dumps(inputs,indent=2)+'\n')
shutil.copy2(__file__,OUT/Path(__file__).name)
print(json.dumps(summary,indent=2))
