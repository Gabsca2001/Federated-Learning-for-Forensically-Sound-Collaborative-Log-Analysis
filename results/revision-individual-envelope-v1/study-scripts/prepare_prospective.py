"""Freeze a three-trajectory persistent-attack study before reserved generation."""
from pathlib import Path
import json
import shutil
import subprocess
import os
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-geometry-detector-v1';prior=out.parent/'current-evidence-policy-20261103'
assert json.loads((lab/'retreat-development-comparison.json').read_bytes())['selected']=='baseline-or-client-retreat'
# Adapt the preserved simulator/controller without altering prior signed files.
shutil.copy(prior/'policy_data.py',out/'policy_data.py')
link=(prior/'worker_link.py').read_text().replace('revision-current-evidence-{role}','revision-envelope-policy-{role}')
(out/'worker_link.py').write_text(link)
controller=(prior/'run_online_study.py').read_text().replace('revision-current-evidence-policy-v1','revision-geometry-detector-v1')
controller=controller.replace('src/fl_forensics/current_evidence_policy.py','src/fl_forensics/client_envelope_policy.py')
controller=controller.replace('random.Random(202611031)','random.Random(202611032)')
controller=controller.replace("assert sha256_file(lab/'policy-calibration/closure.json')==frozen['policy_closure_sha256']",
    "assert sha256_file(lab/'policy-calibration/closure.json')==frozen['policy_closure_sha256']\nassert sha256_file(lab/'policy-calibration/envelope-closure.json')==frozen['envelope_closure_sha256']")
controller=controller.replace("round=number,previous=previous,masses=masses,mandatory_gate={c:True for c in gen.clients})",
    "round=number,previous=previous,masses=masses,mandatory_gate={c:True for c in gen.clients},policy_variant=('prior' if task['branch']=='active-prior' else 'envelope'))")
controller=controller.replace("task['branch']=='active-current-evidence'","task['branch']!='shadow-FedAvg'")
controller=controller.replace("task['branch']!='active-current-evidence'","task['branch']=='shadow-FedAvg'")
controller=controller.replace("'frozen_policy_sha256':sha256_file(lab/'policy-calibration'/f'{cohort}.json'),",
    "'frozen_policy_sha256':sha256_file(lab/'policy-calibration'/f'{cohort}.json'),\n            'frozen_envelope_sha256':sha256_file(lab/'policy-calibration'/f'{cohort}-envelope.json'),")
(out/'run_online_study.py').write_text(controller)
code=lab/'worker-code/fl_forensics';code.mkdir(parents=True)
(code/'__init__.py').write_text('"""Isolated observable-only individual-envelope worker."""\n')
for name in ('state_conditioned_audit.py','sequential_decision.py','current_evidence_policy.py','client_envelope_policy.py'):
    shutil.copy(repo/'src/fl_forensics'/name,code/name)
for name in ('policy_worker.py','fit_client_envelopes.py'):shutil.copy(out/name,lab/'worker-code'/name)
shutil.copytree(repo/'artifacts/revision-sequential-round-policy-v1/policy-calibration',lab/'policy-calibration')
(lab/'inbox').mkdir()
fitroot=lab/'fit-observables'
save(fitroot/'closure.json',{'profile':'observable-only-client-envelope-fit-inputs-v1',
    'files':{p.relative_to(fitroot).as_posix():sha256_file(p) for p in fitroot.rglob('*') if p.is_file()}})
assignments=[['client02','client06','client13'],['client03','client08','client14'],['client01','client09','client15']]
protocol={'profile':'individual-envelope-persistent-attack-study-v1',
    'previous_completion_sha256':sha256_file(prior/'completion-closure.json'),
    'development_comparison_sha256':sha256_file(lab/'development-comparison.json'),
    'retreat_development_comparison_sha256':sha256_file(lab/'retreat-development-comparison.json'),
    'source_policy_sha256':sha256_file(repo/'src/fl_forensics/client_envelope_policy.py'),
    'source_geometry_sha256':sha256_file(repo/'src/fl_forensics/residual_geometry.py'),
    'worker_sha256':sha256_file(out/'policy_worker.py'),'controller_sha256':sha256_file(out/'run_online_study.py'),
    'generator_sha256':sha256_file(out/'policy_data.py'),
    'model_closure_sha256':sha256_file(repo/'artifacts/revision-state-conditioned-heldout-v1/models/model-closure.json'),
    'fit_input_closure_sha256':sha256_file(fitroot/'closure.json'),
    'decision':'Union of original confirmed-current candidates and confirmed non-receding individual-envelope candidates. Geometry-only head rejected on development false positives. Individual raw-risk limits are clean client/view maxima + .05; peak retention .5, two consecutive retained rounds, reset on non-high/unsupported context. Historical evidence cannot authorize action.',
    'horizon':15,'modes':['clean','distributed'],'branches':['shadow-FedAvg','active-prior','active-envelope'],
    'reserved_evaluation':{'iid':list(zip((501593,502593,503593),assignments)),
        'non-iid':list(zip((511593,512593,513593),assignments))},
    'attack_schedules':[list(range(1,13)),list(range(4,16)),[2,3,4,5,6,9,10,11,12,13,14,15]],
    'acceptance_scope':'Count all new-policy shadow proposals on ALL 36 trajectories, not just actual active-envelope exclusions. Compare active prior/envelope numerical outcomes on independently trained paired trajectories.',
    'experimental_acceptance':{
        'zero_never_attacker_envelope_proposals':'All trajectories, including unexecuted new-policy shadow proposals.',
        'zero_currently_clean_scheduled_attacker_envelope_proposals':'All non-attacking rounds, including pre-onset, clean gaps and post-cessation.',
        'shadow_non_iid_recall_strictly_above_prior':'Compare on identical no-intervention shadow prefixes, aggregate three non-IID seeds.',
        'no_active_quorum_failure':'Every active trajectory finishes with minimum 8 positive contributors.',
        'active_envelope_peak_ASR_not_worse_than_prior':'Each of six attacked paired seeds; tolerance only 1e-12.',
        'active_envelope_final_macro_F1_within_0_02_of_prior':'Each of six attacked pairs; absolute drop at most .02.'},
    'no_threshold_or_method_retuning_on_reserved_outcomes':True,'raw_client_rows_accessible_to_worker':False,
    'public_policy_variant_selector':'Worker knows algorithm choice (prior/envelope), never attack mode, seed or schedule.',
    'fresh_TPM_attestation':False,'automatic_live_deployment':False}
save(lab/'protocol-before-new-training.json',protocol)
env={**os.environ,'DOCKER_HOST':'unix:///run/revision-dba-engine.sock','DOCKER_CONFIG':'/tmp/revision-dba-docker-config'}
modelroot=repo/'artifacts/revision-state-conditioned-heldout-v1/models'
command=['docker','create','--name','revision-envelope-fit-20261103','--network','none','--read-only','--cap-drop','ALL',
    '--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}',
    '--tmpfs','/tmp:rw,size=1g','-e','PYTHONPATH=/code','-e','PYTHONDONTWRITEBYTECODE=1','-e','OPENBLAS_NUM_THREADS=1',
    '-v',f'{lab/"worker-code"}:/code:ro','-v',f'{fitroot}:/fit-observables:ro','-v',f'{modelroot}:/models:ro',
    '-v',f'{lab/"policy-calibration"}:/policy-out','sha256:c763483709fabee912591d8b2cd95f06733f381602723244f281bdcb76d0d575','/code/fit_client_envelopes.py']
container=subprocess.check_output(command,env=env,text=True).strip()
save(lab/'fit-runtime-inspection.json',json.loads(subprocess.check_output(['docker','inspect',container],env=env))[0])
run=subprocess.run(['docker','start','-a',container],env=env)
exitcode=int(subprocess.check_output(['docker','inspect','--format','{{.State.ExitCode}}',container],env=env,text=True))
subprocess.run(['docker','rm',container],env=env,check=True,capture_output=True);assert run.returncode==exitcode==0
save(lab/'calibration-frozen-before-evaluation.json',{'policy_closure_sha256':sha256_file(lab/'policy-calibration/closure.json'),
    'envelope_closure_sha256':sha256_file(lab/'policy-calibration/envelope-closure.json'),
    'protocol_sha256':sha256_file(lab/'protocol-before-new-training.json')})
print('PROSPECTIVE THREE-TRAJECTORY PROTOCOL AND ENVELOPES FROZEN',flush=True)
