"""Keep data-only gradient failures and test an explicit gradient-forgery adversary."""
from pathlib import Path
import shutil

out=Path(__file__).parent
p=out/'gradient_study.py'
shutil.copy2(p,out/'gradient_study-development-v2.py')
s=p.read_text().replace("choices=['development','development-v2','evaluation']",
                       "choices=['development','development-v2','development-v3','evaluation']")
s=s.replace("ALPHAS = [0., .25, .5, 1., 2., 4., 16., 64., 128., 256.]",
            "ALPHAS = [0., .03125, .0625, .125, .25, .5, .75, 1., 2., 4.]")
old="""collection_ns = time.perf_counter_ns()-started
        packed"""
new="""endpoint_training_calls = 0
        if active and (root.name.endswith('development-v3') or root.name.endswith('evaluation')):
            _, _, endpoints, endpoint_records = gen.execute(base,task['seed'],number,plan)
            endpoint_training_calls = len(gen.clients)
            arrays = arrays_from_export(base,np=np)
            for c,endpoint in zip(gen.clients,endpoints,strict=True):
                if c in poisoned:
                    local = arrays_from_export(endpoint,np=np)
                    poisoned[c] = [np.asarray((a.astype(np.float64)-b)/.001,dtype=a.dtype)
                                   for a,b in zip(arrays,local,strict=True)]
            save(prefix/'forged-gradient-training-records.json',endpoint_records)
        collection_ns = time.perf_counter_ns()-started
        packed"""
assert s.count(old)==1
s=s.replace(old,new)
s=s.replace("'gradient_endpoints_sha256':sha256_file", "'adversarial_endpoint_training_calls':endpoint_training_calls,'honest_vectors_are_full_snapshot_gradients':True,'adversarial_vectors_are_claimed_gradients_not_derivative_certificates':active,'gradient_endpoints_sha256':sha256_file")
s=s.replace("'attack':'Real clean/50%-DBA-poisoned full-snapshot gradients at current base, with scaled attacker gradient exports. Ten queries/attack round maximize worst full/component validation ASR then scale. Honest gradients are unmodified. No Adam deltas substitute for gradients.'",
"'attack':'Honest clients send actual full-snapshot gradients. Three malicious clients forge claimed gradients from a ten-epoch Adam endpoint trained on 50%-DBA-poisoned local data: (base-poisoned_endpoint)/eta, interpolated with their true clean gradient. This is explicit adversarial gradient replacement, not a claim that Adam deltas are actual derivatives. Ten queries/round with the declared clean-utility guard. Extra adversarial training counted; identical attack recipe/budget for every aggregation method.'")
p.write_text(s)
print('Earlier data-only gradient development retained; gradient forgery has a distinct declared threat model.')
