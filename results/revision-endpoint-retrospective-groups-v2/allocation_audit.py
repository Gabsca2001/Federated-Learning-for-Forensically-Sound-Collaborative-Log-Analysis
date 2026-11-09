"""Audit nominal seeds versus actual allocation memberships; preserve history."""
from pathlib import Path
import sys,json
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O=Path(__file__).parent;sys.path.insert(0,str(R/'scripts'))
from endpoint_group_allocation_guard import allocation_identity
from revision_study_data import read
from fl_forensics.canonical import sha256_file

root=R/'artifacts/revision-capped-final-v1/partitions';records=[]
for p in sorted(root.iterdir()):
    m=read(p/'manifest.json');rows={}
    for c in m['clients']:
        path=p/c['dataset_path'];assert sha256_file(path)==c['dataset_sha256']
        rows[c['client_id']]=read(path)['rows']['train']
    records.append(dict(seed=int(p.name),mode=m['partition_mode'],manifest_sha256=sha256_file(p/'manifest.json'),**allocation_identity(rows)))
groups={}
for x in records:groups.setdefault(x['membership_sha256'],[]).append(x['seed'])
duplicates=[seeds for seeds in groups.values() if len(seeds)>1]
assert next(x for x in records if x['seed']==6116104)['membership_sha256']!=next(x for x in records if x['seed']==6116105)['membership_sha256']
failed=R/'results/revision-endpoint-retrospective-groups-v1';blocked=[]
for p in sorted((failed/'selection-evidence/clean').glob('*.json')):
    value=read(p);blocked.append(dict(seed=int(p.stem),allocation_record=value['allocation']))
result=dict(status='actual_memberships_audited',historical_allocations=records,historical_duplicate_seed_groups=duplicates,
    current_endpoint_source_allocations_distinct=True,blocked_v1_records=blocked,
    blocked_v1_protocol_sha256=sha256_file(failed/'protocol-before-observation.json'),
    reason='The historical Dirichlet generator retries with seed+attempt. Neighboring nominal seeds may converge to the same accepted RNG seed and allocation. Nominal seed inequality cannot establish partition diversity.',
    qualification='Repeated allocations may still have different attacker identities or stochastic training seeds, but cannot count as independent distribution assignments. Historical immutable evidence is unchanged.',
    mitigation='New v2 checks actual allocation membership identities and shared population before training; fitting, calibration and source evaluation allocations must all differ.')
with (O/'allocation-audit.json').open('x') as h:json.dump(result,h,indent=2);h.write('\n')
print(json.dumps(dict(historical_duplicate_seed_groups=duplicates,current_endpoint_source_allocations_distinct=True),indent=2))
