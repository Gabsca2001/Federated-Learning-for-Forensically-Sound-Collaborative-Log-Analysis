"""Freeze the sequential policy study before new calibration or evaluation."""
from pathlib import Path
import shutil
from policy_data import Generator,generate_clean,export_observation,read
from revision_dba_experiment import save,environment
from fl_forensics.canonical import sha256_file

repo=Path.cwd();out=Path(__file__).parent
lab=repo/'artifacts/revision-sequential-round-policy-v1';assert not lab.exists();lab.mkdir()
old=repo/'artifacts/revision-state-conditioned-heldout-v1'
old_completion=out.parent/'state-conditioned-detector-20261103/completion-closure.json'
assert sha256_file(old_completion)=='12cc602c1bfa5fa8cf52e866def2df4f0cdf52c5123cdf68b002b407bb6f50f1'
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
assignments=[['client05','client10','client15'],['client02','client09','client14'],['client01','client08','client12']]
protocol={'profile':'causal-sequential-round-policy-study-v1','previous_completion_sha256':sha256_file(old_completion),
    'model_closure_sha256':sha256_file(old/'models/model-closure.json'),
    'source_policy_sha256':sha256_file(repo/'src/fl_forensics/sequential_decision.py'),
    'predictor_sources':{n:sha256_file(repo/'src/fl_forensics'/n) for n in ('state_conditioned_audit.py','state_conditioned_fusion.py')},
    'generator_sha256':sha256_file(out/'policy_data.py'),'worker_sha256':sha256_file(out/'policy_worker.py'),
    'horizon':15,'CUSUM_drift':.5,'minimum_consecutive_positive_increments':2,
    'normalization':'Per-frame medians and MAD scales (floor .05) from the earlier clean-only observable calibration inputs, distinct from the sequential cutoff inputs.',
    'thresholds':'Separate view maxima over clients and every prefix of new clean 15-round trajectories and prior benign state-response controls; +1 margin. Review uses q.99 + .25. All short prior null sequences are cycled through every start to horizon 15 as dependent null stress, not independent campaigns.',
    'support':'Maximum state distance on declared known-clean normalizer and threshold observations; unsupported inputs reset evidence, require review and cannot trigger statistical quarantine.',
    'decision':'A single-view alert/disagreement is retained for review. Current-round quarantine requires both view CUSUMs above limits, both current increments positive and >=2 consecutive supported positive increments. No permanent bans.',
    'mandatory_gate':'Failure always rejects the contribution with mass zero; changed eligible populations abstain from the fixed-cohort detector. Quorum loss fails aggregation without re-admitting quarantined/rejected inputs.',
    'instantaneous_comparator':'Both current standardized risks above separately calibrated clean maxima. Shadow comparator on the same observed prefixes, not a separate active trajectory.',
    'new_clean_calibration':{'iid':[451593,452593,453593],'non-iid':[454593,455593,456593]},
    'reserved_evaluation':{'iid':list(zip((461593,462593,463593),assignments)),
        'non-iid':list(zip((471593,472593,473593),assignments))},
    'attack_schedules':[list(range(1,11)),list(range(4,13)),list(range(7,15))],
    'branches':['shadow-FedAvg','active-sequential'],'modes':['clean','distributed'],
    'evaluation_rule':'Every prefix uses only current/past observable models; all clients still submit, including clients quarantined in preceding rounds. Model and policy parameters freeze before reserved episodes.',
    'experimental_acceptance':'Zero observed quarantines of never-attacking clients, at least one actually poisoned update quarantined in each attacked episode, and no active quorum failure. Also report exclusions of clean updates from former attackers, reviews, latency, coverage, clean utility and ASR. These finite pilot criteria are not production false-positive guarantees.',
    'raw_data_boundary':'Only the client simulator has snapshots. The persistent detector/decision worker has models, calibration and a one-request observable inbox, never raw rows or attack plans.',
    'fresh_TPM_attestation':False,'live_policy_deployment':False,'training_environment':environment()}
save(lab/'protocol-before-new-training.json',protocol)
code=lab/'worker-code/fl_forensics';code.mkdir(parents=True)
(code/'__init__.py').write_text('"""Isolated observable-only decision worker."""\n')
for name in ('state_conditioned_audit.py','sequential_decision.py'):shutil.copy(repo/'src/fl_forensics'/name,code/name)
shutil.copy(out/'policy_worker.py',lab/'worker-code/policy_worker.py')
(lab/'policy-calibration').mkdir();(lab/'inbox').mkdir()
index={'cohorts':{}}
partitions={'iid':repo/'artifacts/m3-data24-parquet-iid-local-test-v1','non-iid':repo/'artifacts/m3-data24-parquet-non-iid'}
for cohort,partition in partitions.items():
    generator=Generator(partition,cfg);paths=[]
    for seed in protocol['new_clean_calibration'][cohort]:
        observation=generate_clean(generator,lab/'private-calibration'/cohort/f'cal-{seed}',seed)
        destination=lab/'calibration-observations'/cohort/f'cal-{seed}';export_observation(destination,observation)
        paths.append(destination.relative_to(lab).as_posix())
    index['cohorts'][cohort]={'cohort_id':sha256_file(partition/'manifest.json'),'new_clean_threshold_inputs':paths}
save(lab/'new-clean-calibration-index.json',index)
print('NEW SEQUENTIAL CLEAN CALIBRATION READY',flush=True)
