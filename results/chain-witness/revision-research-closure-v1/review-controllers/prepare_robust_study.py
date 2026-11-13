"""Prepare a separately named robust-aggregation study without rewriting old results."""
from pathlib import Path

out=Path(__file__).parent
s=(out.parent/'independent-validation-20261104/run.py').read_text()
s=s.replace("from common import context,score,aggregate,read", "from common import context,score,aggregate as old_aggregate,read")
s=s.replace("repo=Path.cwd();lab=repo/'artifacts/revision-independent-containment-v1'", """import argparse
from fl_forensics.robust_bounded_aggregation import aggregate_robust_bounded,verify_robust_bounded
from fl_forensics.bounded_aggregation import digest

parser=argparse.ArgumentParser();parser.add_argument('--phase',choices=['development','evaluation'],required=True)
phase=parser.parse_args().phase
repo=Path.cwd();lab=repo/'artifacts/revision-research-closure-v1'/('robust-'+phase)

def aggregate(base,exports,gen,excluded,bounded,reference):
    if task['strategy']=='bounded-envelope':
        return old_aggregate(base,exports,gen,excluded,True,reference)
    arrays=arrays_from_export(base,np=np)
    updates={c:arrays_from_export(e,np=np) for c,e in zip(gen.clients,exports,strict=True)}
    args=dict(masses={c:0 if c in excluded else len(gen.rows[c]) for c in gen.clients},
              mandatory_gates=dict.fromkeys(gen.clients,True),limits=reference['limits'],
              reference_digest=digest(reference),minimum_contributors=8)
    parameters,report=aggregate_robust_bounded(arrays,updates,**args)
    repeated=verify_robust_bounded(arrays,updates,report,**args)
    if parameters is None:return None,report,None
    assert all(np.array_equal(a,b) for a,b in zip(parameters,repeated,strict=True))
    model=model_with_arrays(base,parameters)
    # No old certificate is silently assigned to recomputed robust weights.
    certificate={'profile':'robust-convex-coefficient-certificate-v1','per_client':{},
        'weights':report['final_coefficients'],
        'scope':'Finite robust output replay. Fixed-coefficient removal certificates are constructed separately; no dynamic robust reweighting bound is claimed.'}
    return model,report,certificate
""")
s=s.replace("assert implementation_sha256()=='4b58e1590179dbaa37c8e9760b94bd57549db6c3a228e95f00ee2def26012bbb'", "frozen_source=implementation_sha256()")
a=s.index("assignments=[")
b=s.index("tasks=[",a)
s=s[:a]+"""assignments=([('non-iid',2026110406,['client04','client07','client11'])] if phase=='development' else
             [('iid',2026110451,['client03','client08','client13']),
              ('iid',2026110452,['client02','client07','client15']),
              ('iid',2026110453,['client01','client09','client12']),
              ('non-iid',2026110454,['client02','client08','client14']),
              ('non-iid',2026110455,['client04','client06','client15']),
              ('non-iid',2026110456,['client03','client07','client12'])])

"""+s[b:]
s=s.replace("('envelope','bounded-envelope')", "('bounded-envelope','robust-bounded-envelope')")
s=s.replace("'profile':'independent-multitrigger-containment-v1'", "'profile':'robust-convex-containment-comparison-v1','phase':phase")
s=s.replace("'defense_fitting_performed':False", "'defense_fitting_performed':False,'robust_operator':'Fixed 50-iteration-cap smoothed geometric-median reweighting of the same bounded deltas. Same mandatory/envelope gates. New convex weights are recorded; no malicious-client classification claim.'")
s=s.replace("'independence':'Six newly reserved cohort/seed/identity combinations; defense and attack rule frozen before these observations. Same underlying Data24 splits and partitions, not a new independent dataset.'", "'independence':'Development reuses one disclosed earlier counterexample; evaluation reserves six new seed/identity assignments after development. Same Data24 partitions, not an independent dataset.'")
s=s.replace("(out/'protocol-before-training.json').write_bytes((lab/'protocol-before-training.json').read_bytes())", "(out/f'robust-{phase}-protocol.json').write_bytes((lab/'protocol-before-training.json').read_bytes())\n(lab/'controller.py').write_bytes(Path(__file__).read_bytes())")
s=s.replace("bounded=task['strategy']=='bounded-envelope'", "bounded=True")
s=s.replace("(out/'results.json').write_bytes((lab/'results.json').read_bytes())", "(out/f'robust-{phase}-results.json').write_bytes((lab/'results.json').read_bytes())")
s=s.replace("INDEPENDENT VALIDATION COMPLETE", "ROBUST COMPARISON COMPLETE")
(out/'robust_study.py').write_text(s)
print('Robust study prepared as a separate profile; former validation retained.')
