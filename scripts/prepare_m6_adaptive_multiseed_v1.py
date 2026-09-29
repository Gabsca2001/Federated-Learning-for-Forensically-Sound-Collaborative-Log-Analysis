"""Freeze the four-seed extension before any new training."""
from pathlib import Path
import json,hashlib,subprocess,datetime
import yaml
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
def write(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2);f.write('\n')
base=read(ROOT/'configs/m6-adaptive-paired-s341593-v4.json')
seeds=[342593,343593,344593,345593]
plans=[]
reference=yaml.safe_load((ROOT/'configs/federation.yaml').read_text())
for seed in seeds:
    p=dict(base);tag=f'm6-adaptive-paired-s{seed}-v1'
    p.update(experiment_id=tag,seed=seed,trust_tag=tag,partition=f'artifacts/m6-policy-partition-s{seed}-v1',federation_config=f'configs/federation-m6-policy-seed-{seed}.yaml',node_lifecycle='fresh TPM identities per pair; never restart during pair; stop after both final verifications',scope='Prespecified four-seed extension after exploratory seed 341593; prior dataset reuse, not confirmatory.')
    fc=yaml.safe_load((ROOT/p['federation_config']).read_text())
    assert fc['training']['seed']==fc['partitioning']['seed']==seed
    fc['training']['seed']=reference['training']['seed'];fc['partitioning']['seed']=reference['partitioning']['seed']
    assert fc==reference,'Non-seed federation difference'
    part=read(ROOT/p['partition']/'manifest.json'); assert part['seed']==seed and part['partition_mode']=='iid'
    path=f'configs/{tag}.json';write(ROOT/path,p);plans.append(path)
protocol='''# Adaptive multiseed extension v1 — prespecified 2026-09-29

Seed 341593 is the completed exploratory v4 reference, whose outcomes are already
known. Four new seeds (342593, 343593, 344593, 345593) are fixed before their runs.
Report all five paired differences and clearly distinguish the initial reference
from the four subsequent replicas; do not present this as a fresh confirmatory study.

Each new seed uses its existing verified IID partition and CPU federation config;
only training/partition seeds change. Clean and adaptive arms share the partition,
training configuration, immutable image and single-thread numerical runtime. Both
run 30 rounds, paired round by round, with exact checkpoint equality at rounds 1–10.
The adaptive arm uses the same three clients, target, search algorithm, oracle,
66-query budget, feasibility rule and original gated-composite policy in rounds
11–30. No post-test tuning, new attack objective, budget expansion or early stopping
based on attack success. Failed searches remain failures and all outputs retained.

Primary endpoints: selected-checkpoint pooled test ASR reconnaissance→benign and
macro-F1, paired adaptive-minus-clean differences. Selection is max validation
macro-F1, earliest tie; test only after both full trajectories and verifications.
Describe mean, sample SD and individual differences; rounds and queries are not
independent experimental replicates. Five seeds remain a small sample. Report
validation trajectories, within-state attack effects, attacker/honest admissions
with denominators, computational cost and every execution failure.

New TPMs and distinct workspaces per pair. Official M4 provisioning with local
verified images and --skip-build; existing M5 commands and independent v4 verifier.
Do not restart TPMs, weaken verification or overwrite a partial workspace. Stop at
first error for diagnosis. Existing empty historical Docker trust networks may be
released only after saving inspection and confirming no attached/running containers;
no evidence, containers or volumes are deleted by that step.

The extension adds 240 rounds (eight arms) and 5,280 attack search queries, plus
independent recomputation. It does not include a no-statistical-filter ablation or
a different poisoning strategy; those require separately fixed protocols.
'''
with (ROOT/'docs/M6_ADAPTIVE_MULTISEED_V1.md').open('x') as f:f.write(protocol)
files=[ROOT/p for p in plans]+[ROOT/'docs/M6_ADAPTIVE_MULTISEED_V1.md',ROOT/'scripts/run_m6_adaptive_paired_seed.py',ROOT/'scripts/run_m6_adaptive_multiseed_v1.py',ROOT/'scripts/verify_m6_adaptive_paired_v4.py',ROOT/'scripts/m6_adaptive_live_search.py',ROOT/'scripts/m6_adaptive_live_signing.py',ROOT/'scripts/m6_numeric_runtime.py',ROOT/'scripts/run_m4_swtpm.py',ROOT/'scripts/run_m5_secure_multiround.py',ROOT/'configs/m6-adaptive-frozen-pilot-v1.json',ROOT/'configs/in-round-admission.yaml',ROOT/'configs/secure-round.yaml',ROOT/'configs/trust.yaml',ROOT/'compose.m4.yaml',ROOT/'compose.m5.yaml',ROOT/'results/m6-numeric-runtime-preflight-v1/summary.json']
files+=list((ROOT/'src/fl_forensics').glob('*.py'))
for path in plans:
    p=read(ROOT/path);files.extend([ROOT/p['federation_config'],ROOT/p['partition']/'manifest.json',ROOT/p['partition']/'server/splits/validation.json'])
write(ROOT/'configs/m6-adaptive-multiseed-v1.lock.json',dict(created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),new_seeds=seeds,plans=plans,known_reference='artifacts/m6-adaptive-paired-s341593-v4',files={str(p.relative_to(ROOT)):sha(p) for p in files}))
print('Four-seed protocol frozen; no training started.')