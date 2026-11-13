"""Cross-seed development diagnosis; labels are read only after selection closes."""
import json
from pathlib import Path

from revision_dba_experiment import authenticate, save
from revision_group_analysis import load_rounds
from fl_forensics.canonical import sha256_file
from fl_forensics.retrospective_groups import calibrate_groups, detect_groups

root=Path('artifacts/revision-dba-three-seed-v1')
out=Path('artifacts/revision-group-diagnosis-v2')
out.mkdir(exist_ok=False)
seeds=(341593,342593,343593)


def read(path):
    return json.loads(path.read_bytes())


sources={}
pins={}
for seed in seeds:
    for mode in ('clean','distributed'):
        name=f'{mode}-s{seed}'; creation=read(root/'reports'/f'{name}.json')['creation']
        assert sha256_file(root/name/'experiment-authority.public.pem')==creation['public_key_sha256']
        authenticate(root/name,creation['manifest_sha256']); pins[name]=creation
        sources[name]=load_rounds(root/name)[:10]
save(out/'protocol-before-selection.json',{'profile':'cross-seed-group-development-diagnosis-v1',
    'source_pins':pins,'endpoint':10,'split':'For each seed, calibrate on clean trajectories from the other two seeds; evaluate the held-out clean trajectory and the attacked trajectory. These already used seeds are a development diagnostic, not an untouched final test.',
    'selection':'Unchanged v1 observable-only detector; no identity labels or ASR are passed to it.',
    'interpretation':'Client pairs share campaigns and are dependent; no pair-independent false-positive confidence claim.'})
results=[]
for seed in seeds:
    calibration=calibrate_groups([sources[f'clean-s{s}'] for s in seeds if s!=seed])
    for mode in ('clean','distributed'):
        selected=detect_groups(sources[f'{mode}-s{seed}'],calibration)
        save(out/f'{mode}-s{seed}-selection-before-labels.json',{'calibration':calibration,'selection':selected})
        results.append({'seed':seed,'mode':mode,'calibration':calibration,'selection':selected})
# The durable label-blind outputs above cannot be replaced during evaluation.
evaluation=[]
for result in results:
    seed=result['seed']; mode=result['mode']; selected=result['selection']
    truth=set(read(root/f'distributed-s{seed}'/'protocol-before-training.json')['attack_plan']['client_components']) if mode=='distributed' else set()
    flagged=set(c for group in selected['candidate_groups'] for c in group)
    tp=len(flagged&truth); fp=len(flagged-truth); fn=len(truth-flagged)
    details=[{**p,'score_threshold':result['calibration']['score_threshold'],'thresholds':result['calibration']['feature_thresholds']} for p in selected['pairs'] if set(p['clients'])<=truth]
    evaluation.append({'seed':seed,'mode':mode,'candidate_groups':selected['candidate_groups'],'tp':tp,'fp':fp,'fn':fn,
        'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None,
        'campaign_alarm':bool(flagged),'true_attacker_pair_diagnostics':details})
save(out/'evaluation.json',{'profile':'cross-seed-group-development-diagnosis-v1','cases':evaluation,
    'intentional_collusion_proved':False,'unseen_final_test':False})
target=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/residual-poisoning-20261103')
(target/'group-development-diagnosis.json').write_text(json.dumps({'cases':evaluation},indent=2,sort_keys=True)+'\n')
for item in evaluation:
    print(json.dumps(item),flush=True)
