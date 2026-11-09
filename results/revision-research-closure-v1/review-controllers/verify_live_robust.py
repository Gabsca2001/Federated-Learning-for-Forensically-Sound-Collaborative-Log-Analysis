"""Check actual signed originals, finite robust reports, exported models and graph bindings."""
from pathlib import Path
from fractions import Fraction
import copy
import json
import numpy as np

from fl_forensics.bounded_aggregation import aggregate_bounded,digest
from fl_forensics.robust_bounded_aggregation import aggregate_robust_bounded,verify_robust_bounded
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.storage import load_json,write_once

root=Path('/evidence');results=[];certificates=mutations=0
for branch in ('clean','control','active'):
    for number in range(1,6):
        w=root/'branches'/branch/'rounds'/f'round-{number:03d}'
        base=load_json(w/'public/base-model.json');ba=arrays_from_export(base,np=np)
        cap=load_json(w/'public/observable-assets/bounds.json')
        decisions={p.stem:load_json(p)['core'] for p in (w/'in-round-decisions').glob('*.json')}
        updates={c:arrays_from_export(load_json(w/'submissions'/c/'update.json'),np=np) for c in decisions}
        value=load_json(w/'bounded-update-derivation.json')
        for c in decisions:
            assert value['source_bundles'][c]==sha256_file(w/'submissions'/c/'bundle.json')
            assert value['source_updates'][c]==sha256_file(w/'submissions'/c/'update.json')
        args=dict(masses={c:d['effective_weight_decimal'] for c,d in decisions.items()},
            mandatory_gates={c:all(ch['passed'] for ch in d['m5_checks']) for c,d in decisions.items()},
            limits=cap['limits'],reference_digest=digest(cap),
            minimum_contributors=load_json(w/'public/in-round-admission-contract.json')['core']['minimum_contributors'])
        robust=branch!='control'; op=aggregate_robust_bounded if robust else aggregate_bounded
        pre,report=op(ba,updates,**args);assert report==value['bounded']
        expected=copy.deepcopy(base)
        for p,a in zip(expected['parameters'],pre,strict=True):p['values']=np.asarray(a,dtype=np.dtype(p['dtype'])).tolist()
        assert derived_json_bytes(expected)==(w/'checkpoint/global-model.json').read_bytes()
        core=load_json(w/'checkpoint/manifest.json')['core']
        assert core['aggregation_strategy']==('RobustBoundedDelta-GeometricMedian-observable-envelope' if robust else 'BoundedDelta-FedAvg-observable-envelope')
        nodes=load_json(w/'derivation/manifest.json')['core']['nodes']
        assert any(n['kind']=='bounded_update_derivation' and n['sha256']==sha256_file(w/'bounded-update-derivation.json') for n in nodes)
        row={'branch':branch,'round':number,'exact_checkpoint':True,'graph_binding':True,
             'checkpoint_sha256':sha256_file(w/'checkpoint/manifest.json'),'frozen_beta_certificates':{}}
        if robust:
            final=report['final_bounded_derivation'];actual=arrays_from_export(expected,np=np)
            epsfull=np.array([np.linalg.norm(a.astype(float)-b) for a,b in zip(actual,pre,strict=True)])
            mu=[a-b.astype(float) for a,b in zip(pre,ba,strict=True)]
            for c,item in final['contributions'].items():
                beta=float(Fraction(item['normalized_weight']))
                if beta==0:continue
                delta=[np.asarray(t['values']).reshape(t['shape']) for t in item['derived_float64_delta']]
                assert all(np.linalg.norm(d)<=C+1e-12 for d,C in zip(delta,cap['limits'],strict=True))
                assert beta<1
                survivor=[b.astype(float)+(m-beta*d)/(1-beta) for b,m,d in zip(ba,mu,delta,strict=True)]
                exported=[a.astype(np.dtype(p['dtype'])) for a,p in zip(survivor,base['parameters'],strict=True)]
                eps=np.array([np.linalg.norm(a.astype(float)-b) for a,b in zip(exported,survivor,strict=True)])
                distance=np.array([np.linalg.norm(a.astype(float)-b.astype(float)) for a,b in zip(actual,exported,strict=True)])
                bound=2*beta*np.asarray(cap['limits'])+epsfull+eps
                assert np.all(distance<=bound+1e-12)
                survivor_quorum=sum(Fraction(x['effective_mass'])>0 for cid,x in final['contributions'].items() if cid!=c)>=args['minimum_contributors']
                row['frozen_beta_certificates'][c]={'distance':distance.tolist(),'bound_with_rounding':bound.tolist(),'survivor_quorum':survivor_quorum}
                certificates+=1
            changed=copy.deepcopy(report);client=next(iter(changed['final_coefficients']));changed['final_coefficients'][client]='17/19'
            try:verify_robust_bounded(ba,updates,changed,**args)
            except ValueError:mutations+=1
            else:raise AssertionError('Changed final robust coefficient accepted')
            row['converged']=report['converged'];row['iterations']=report['iterations']
        results.append(row)
record={'status':'verified','source':implementation_sha256(),'rounds':results,
        'round_count':len(results),'robust_rounds':sum(r['branch']!='control' for r in results),
        'fixed_final_beta_removal_certificates':certificates,'coefficient_mutations_rejected':mutations,
        'scope':'Actual retained originals to named transformation, exact checkpoint export and typed graph binding. Fixed-final-beta certificates include both export-rounding errors and 1e-12 allowance. No recomputed-weight, semantic malice or ASR guarantee. Fresh software TPMs are emulations on one host.'}
write_once(root/'reports/robust-profile-verification.json',derived_json_bytes(record))
print(json.dumps({k:v for k,v in record.items() if k!='rounds'}),flush=True)
