"""Freeze development design and generate clean-only state stress controls."""
from pathlib import Path
import json
from study_data import Generator,load_observation,export_observation,read,get_observation
from revision_dba_experiment import authenticate,save
from fl_forensics.canonical import sha256_file

repo=Path.cwd();lab=repo/'artifacts/revision-state-conditioned-development-v1'
old=repo/'artifacts/revision-dba-three-seed-v1';v2=repo/'artifacts/revision-conditioned-groups-v2-fixed-serialization'
assert not lab.exists();lab.mkdir()
cfg=read(old/'distributed-s341593/protocol-before-training.json')
save(lab/'protocol-before-stress-training.json',{'profile':'state-conditioned-development-v1',
    'role':'Development only: all six evaluation trajectories have already been seen in V2; they cannot be called held-out in this study.',
    'fit_normal_seeds':[341593,342593,343593],'calibration_normal_seeds':[351593,352593,353593],
    'development_seeds':[361593,362593,363593],'fit_stress_count':32,'calibration_stress_count':20,
    'stress_seeds':[401593,402593],'ridge':.1,'risk_quantile':.8,
    'hypothesis':'Client/layer isotropic response plus low-rank ridge correction conditioned on incoming global model, then robust common residual centering; compare a state-disabled ablation.',
    'generator_sha256':sha256_file(Path(__file__).parent/'study_data.py'),'controller_sha256':sha256_file(Path(__file__))})
fit=[];anchors=[]
for seed in (341593,342593,343593):
    workspace=old/f'clean-s{seed}';pin=read(old/'reports'/f'clean-s{seed}.json')['creation']
    assert sha256_file(workspace/'experiment-authority.public.pem')==pin['public_key_sha256']
    authenticate(workspace,pin['manifest_sha256'])
    obs=load_observation(workspace);fit.append(obs);anchors.extend(obs['anchors'])
    export_observation(lab/'observable-fit'/f'normal-{seed}',obs)
for seed in (351593,352593,353593):
    workspace=v2/f'clean-s{seed}';authenticate(workspace,sha256_file(workspace/'manifest.json'))
    export_observation(lab/'observable-calibration'/f'normal-{seed}',load_observation(workspace))
generator=Generator(cfg['partition_workspace'],cfg)
stress=generator.stress(lab/'generated/fit-stress',anchors,32,401593)
export_observation(lab/'observable-fit/stress',stress)
stress=generator.stress(lab/'generated/calibration-stress',anchors,20,402593)
for index in range(2):
    obs={**stress,'states':stress['states'][index*10:(index+1)*10],
        'updates':stress['updates'][index*10:(index+1)*10],'source':stress['source'][index*10:(index+1)*10]}
    export_observation(lab/'observable-calibration'/f'stress-{index}',obs)
for seed in (361593,362593,363593):
    for mode in ('clean','distributed'):
        workspace=v2/f'{mode}-s{seed}';authenticate(workspace,sha256_file(workspace/'manifest.json'))
        export_observation(lab/'observable-development'/f'{mode}-{seed}',load_observation(workspace))
save(lab/'generation-completion.json',{'new_local_training_calls':780,'generated_clean_contexts':52,
    'observable_exports_contain_raw_rows':False,'profile':'state-conditioned-development-v1'})
print('DEVELOPMENT OBSERVATIONS READY',flush=True)
