"""Freeze final protocol and build disjoint clean inputs before held-out cases."""
from pathlib import Path
import shutil
import hashlib
from study_data import Generator,read,load_observation,export_observation
from revision_dba_experiment import save,environment
from fl_forensics.canonical import sha256_file

repo=Path.cwd();out=Path(__file__).parent
lab=repo/'artifacts/revision-state-conditioned-heldout-v1';assert not lab.exists();lab.mkdir()
development=repo/'artifacts/revision-state-conditioned-development-v1'
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
partitions={'iid':repo/'artifacts/m3-data24-parquet-iid-local-test-v1',
            'non-iid':repo/'artifacts/m3-data24-parquet-non-iid'}
assignments=[['client02','client07','client12'],['client03','client08','client13'],['client04','client09','client14']]
protocol={'profile':'frozen-dual-view-state-audit-evaluation-v1',
    'development_role':'V1 and fusion selected using previously seen IID seeds 361593–363593. Those cases are development, never held-out results here.',
    'algorithms':{n:sha256_file(repo/'src/fl_forensics'/n) for n in ('state_conditioned_audit.py','state_conditioned_fusion.py')},
    'generator_sha256':sha256_file(out/'study_data.py'),'controller_sha256':sha256_file(Path(__file__)),
    'incoming_model_conditioning':'Client/layer scalar clean secant response plus ridge correction on global checkpoint; residual common-mode median removal.',
    'fixed_parameters':{'ridge':.1,'risk_quantile':.8,'leaf_margin':1.,'joint_margin':1.,'state_support':'maximum on separate clean calibration frames','minimum_supported_frames':3},
    'training':{k:cfg[k] for k in ('local_epochs','batch_size','learning_rate','base_model_sha256','validation_sha256')},
    'cohorts':{name:{'partition_manifest_sha256':sha256_file(path/'manifest.json'),'partition_strategy':read(path/'manifest.json')['partition_strategy'],
        'train_row_counts':{r['client_id']:r['train_row_count'] for r in read(path/'manifest.json')['clients']}} for name,path in partitions.items()},
    'iid_fit_calibration':'Reuse closed clean development inputs: normal fit 341593–343593 plus stress 401593; normal calibration 351593–353593 plus stress 402593.',
    'non_iid_fit_seeds':[411593,412593,413593],'non_iid_calibration_seeds':[421593,422593,423593],
    'non_iid_stress_seeds':[414593,424593],'stress_context_counts':[32,20],
    'heldout':{'iid':list(zip((431593,432593,433593),assignments)),
               'non-iid':list(zip((441593,442593,443593),assignments))},
    'horizon':10,'attack_rounds':list(range(1,11)),'poisoned_fraction':'.50','target':'benign',
    'trigger':'Same known experimental features/values as development; trigger novelty is not evaluated.',
    'ablation':'State-conditioned, state-disabled and geometric-mean dual view, each frozen from clean fitting/calibration. No labels or ASR enter selection.',
    'evaluation':'Client TP/FP/FN, exact membership, campaign alarms, support/abstention coverage on every case including weak or unsuccessful attacks; all 3223 existing validation examples for outcomes; no final-test access.',
    'privacy':'Fitting, calibration and inference run in a network-disabled read-only container without original client datasets or generation/evaluation labels mounted.',
    'models_frozen_before_heldout_generation':True,'fresh_TPM_attestation':False,'environment_for_training':environment()}
save(lab/'frozen-protocol-before-new-training.json',protocol)
code=lab/'detector-code/fl_forensics';code.mkdir(parents=True)
(code/'__init__.py').write_text('"""Isolated server-observable analysis package."""\n')
for name in ('state_conditioned_audit.py','state_conditioned_fusion.py'):
    shutil.copy(repo/'src/fl_forensics'/name,code/name)
shutil.copy(out/'run_isolated_detector.py',lab/'detector-code/run_isolated_detector.py')
index={'profile':'observable-only-fit-inputs-v1','cohorts':{}}
for cohort,partition in partitions.items():
    public_cohort=sha256_file(partition/'manifest.json')
    fit_paths=[];cal_paths=[]
    if cohort=='iid':
        for role,paths in (('fit',fit_paths),('calibration',cal_paths)):
            for path in sorted((development/f'observable-{role}').iterdir()):
                destination=lab/'observable-inputs'/cohort/role/path.name
                shutil.copytree(path,destination)
                paths.append(destination.relative_to(lab).as_posix())
    else:
        generator=Generator(partition,cfg);anchors=[]
        for role,seeds,paths in (('fit',(411593,412593,413593),fit_paths),('calibration',(421593,422593,423593),cal_paths)):
            for seed in seeds:
                obs=generator.campaign(lab/'private-generation'/cohort/f'{role}-{seed}',seed)
                destination=lab/'observable-inputs'/cohort/role/f'normal-{seed}'
                export_observation(destination,obs);paths.append(destination.relative_to(lab).as_posix())
                if role=='fit':anchors.extend(obs['anchors'])
        for role,seed,count,paths in (('fit',414593,32,fit_paths),('calibration',424593,20,cal_paths)):
            obs=generator.stress(lab/'private-generation'/cohort/f'{role}-stress',anchors,count,seed)
            for offset in range(1 if role=='fit' else 2):
                piece=obs if role=='fit' else {**obs,'states':obs['states'][offset*10:(offset+1)*10],
                    'updates':obs['updates'][offset*10:(offset+1)*10],'source':obs['source'][offset*10:(offset+1)*10]}
                destination=lab/'observable-inputs'/cohort/role/f'stress-{offset}'
                export_observation(destination,piece);paths.append(destination.relative_to(lab).as_posix())
    index['cohorts'][cohort]={'cohort_id':public_cohort,'fit':fit_paths,'calibration':cal_paths}
save(lab/'fit-input-index.json',index)
save(lab/'fit-input-closure.json',{'files':{p.relative_to(lab).as_posix():sha256_file(p) for p in (lab/'observable-inputs').rglob('*') if p.is_file()},
    'index_sha256':sha256_file(lab/'fit-input-index.json'),'code':{p.relative_to(lab).as_posix():sha256_file(p) for p in (lab/'detector-code').rglob('*.py')}})
print('FINAL CLEAN INPUTS READY',flush=True)
