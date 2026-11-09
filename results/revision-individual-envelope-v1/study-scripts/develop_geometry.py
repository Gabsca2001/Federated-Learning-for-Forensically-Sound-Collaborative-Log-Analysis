"""Clean fit and fixed candidate comparison on explicitly reused observations."""
from pathlib import Path
import json
import numpy as np
from study_data import get_observation,read
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file
from fl_forensics.state_conditioned_audit import load_model
from fl_forensics.residual_geometry import fit_geometry,geometry_scores,save_geometry

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-geometry-detector-v1'
assert not lab.exists();lab.mkdir()
prior=out.parent/'current-evidence-policy-20261103'
assert sha256_file(prior/'completion-closure.json')=='4ef209ad006da39251ddb6ef6cf2abbe9bd0e945e2797e23202a162301faf1e2'
for name,value in read(prior/'completion-closure.json')['core']['artifacts'].items():assert sha256_file(prior/name)==value
old=repo/'artifacts/revision-state-conditioned-heldout-v1'
seq=repo/'artifacts/revision-sequential-round-policy-v1'
roots=[seq,repo/'artifacts/revision-current-evidence-policy-v1']
candidates=['baseline','clientwise','geometry','intersection','baseline-or-intersection','baseline-or-geometry']
save(lab/'development-protocol-before-fit.json',{'profile':'geometry-development-selection-v1',
    'source_sha256':sha256_file(repo/'src/fl_forensics/residual_geometry.py'),
    'candidate_rules':candidates,'source_previous_completion_sha256':sha256_file(prior/'completion-closure.json'),
    'normalizer':'Five original clean reference-normalization sequences per cohort, disjoint from predictor fit.',
    'null_controls':'Original clean and matched-state clean controls, six extra clean calibration episodes, plus clean shadow episodes from the two previous policy studies. All are now development data.',
    'geometry':'Every matrix row and column, every vector tensor; per-client coordinate median/MAD whitening, tensor-relative noise floor .1, group log1p RMS median/MAD scaling (.05 floor), same-group minimum across both predictor views. Per-client/group clean maximum plus 1.',
    'clientwise':'Both tensor residual risks exceed their per-client clean null maxima plus .05 in two consecutive supported rounds.',
    'geometry_confirmation':'The SAME group must exceed its joint limit in two consecutive supported rounds; memory never authorizes quarantine.',
    'selection':'Keep only candidates with zero never-attacker or currently-clean scheduled-attacker proposals across all 48 old cases and no quorum loss; maximize poisoned proposals on old shadow cases; tie chooses fewer geometry groups/structural complexity in candidate order. If no candidate qualifies, keep baseline and report no selection success.',
    'fresh_evaluation_data_used':False,'raw_client_rows_used':False})
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
shapes=[p['shape'] for p in read(Path(cfg['base_model_path']))['parameters']]
initial_index=read(old/'fit-input-index.json');old_rows=read(old/'post-selection-evaluation.json')['rows']
new_index=read(seq/'new-clean-calibration-index.json');inputs={'cohorts':{}}

def obs(path,cohort_id):return {**get_observation(path),'cohort_id':cohort_id}
def episode_obs(episode,cohort_id):
    parts=[get_observation(p/'observable') for p in sorted((episode/'rounds').glob('round-*'))]
    return {'clients':parts[0]['clients'],'sizes':parts[0]['sizes'],'cohort_id':cohort_id,
        'states':np.concatenate([p['states'] for p in parts]),'updates':np.concatenate([p['updates'] for p in parts])}

models_by_cohort={};ref_by_cohort={};summary=[]
for cohort in ('iid','non-iid'):
    models={v:load_model(old/'models'/cohort/f'{v}.npz') for v in ('conditioned','state-disabled')}
    cid=models['conditioned']['schema']['cohort_id']
    normpaths=[old/p for p in initial_index['cohorts'][cohort]['calibration']]
    nullpaths=[old/'observable-inference'/r['alias'] for r in old_rows if r['cohort']==cohort and r['method']=='fusion' and r['mode'] in ('clean','matched-state-clean')]
    nullpaths += [seq/p for p in new_index['cohorts'][cohort]['new_clean_threshold_inputs']]
    extra=[]
    for root in roots:
        for t in read(root/'reserved-execution-before-training.json')['tasks']:
            if t['cohort']==cohort and t['mode']=='clean' and t['branch']=='shadow-FedAvg':extra.append(root/'private-episodes'/t['stream'])
    norms=[obs(p,cid) for p in normpaths]
    nulls=[obs(p,cid) for p in nullpaths]+[episode_obs(p,cid) for p in extra]
    inputs['cohorts'][cohort]={'normalizer_paths':[str(p) for p in normpaths],
        'null_paths':[str(p) for p in nullpaths],'extra_clean_episode_paths':[str(p) for p in extra],
        'public_shapes':shapes,'model_cohort_id':cid}
    reference=fit_geometry(norms,nulls,models,shapes)
    dest=lab/'development-models'/cohort;dest.mkdir(parents=True)
    save_geometry(dest/'geometry.npz',reference)
    # Store clean calibration arrays for independent isolated re-fitting later.
    for role,observations in [('normalizer',norms),('null',nulls)]:
        target=lab/'fit-observables'/cohort/role;target.mkdir(parents=True)
        for i,o in enumerate(observations):
            np.savez_compressed(target/f'{i:03d}.npz',states=o['states'],updates=o['updates'])
    save(lab/'fit-observables'/cohort/'schema.json',{'clients':reference['schema']['clients'],'sizes':reference['schema']['sizes'],
        'cohort_id':cid,'shapes':shapes,'normalizer_files':len(norms),'null_files':len(nulls)})
    print(json.dumps({'fitted':cohort,'groups':len(reference['groups']),'normalizer_frames':len(reference['normalizer_frame_ids']),
        'unique_null_frames':len(reference['threshold_frame_ids'])}),flush=True)
    # Evaluate all historical cases without retraining or reading original rows.
    for root in roots:
        oldcal=read(seq/'policy-calibration'/f'{cohort}.json')
        for task in read(root/'reserved-execution-before-training.json')['tasks']:
            if task['cohort']!=cohort:continue
            observation=episode_obs(root/'private-episodes'/task['stream'],cid)
            scored=geometry_scores(observation,models,reference)
            raw=scored['tensor_risk'];z=np.maximum(0.,(raw-np.asarray(oldcal['centers']))/np.asarray(oldcal['scales']))
            baseline_high=(z>np.asarray(oldcal['instantaneous_limits'])).all(axis=2)
            tensor_high=(raw>reference['tensor_risk_limits']).all(axis=2)
            group_high=scored['group_excess']>0
            previous_b=np.zeros(15,dtype=bool);previous_t=previous_b.copy();previous_g=np.zeros_like(group_high[0])
            counts={name:{'tp':0,'never':0,'clean_scheduled':0,'quorum_failures':0} for name in candidates}
            for number in range(15):
                if not scored['supported'][number]:
                    previous_b[:]=False;previous_t[:]=False;previous_g[:]=False;continue
                b=baseline_high[number]&previous_b;t=tensor_high[number]&previous_t
                g=(group_high[number]&previous_g).any(axis=1)
                selected={'baseline':b,'clientwise':t,'geometry':g,'intersection':t&g,
                    'baseline-or-intersection':b|(t&g),'baseline-or-geometry':b|g}
                intended=set(task['attackers']) if task['mode']=='distributed' else set()
                active=intended if number+1 in task['attack_rounds'] else set()
                for name,mask in selected.items():
                    names={c for c,yes in zip(observation['clients'],mask,strict=True) if yes}
                    counts[name]['tp']+=len(names&active);counts[name]['never']+=len(names-intended)
                    counts[name]['clean_scheduled']+=len((names&intended)-active)
                    counts[name]['quorum_failures']+=int(15-len(names)<8)
                previous_b=baseline_high[number].copy();previous_t=tensor_high[number].copy();previous_g=group_high[number].copy()
            summary.append({'source_root':root.name,'task':task,'methods':counts})
            print(json.dumps({'scored':root.name+'/'+task['stream'],'cohort':cohort,'methods':counts}),flush=True)
    # Free large frozen predictor arrays before loading the next cohort.
    del models,reference
save(lab/'development-inputs.json',inputs)
totals={name:{k:sum(r['methods'][name][k] for r in summary) for k in ('tp','never','clean_scheduled','quorum_failures')} for name in candidates}
for name in candidates:totals[name]['shadow_tp']=sum(r['methods'][name]['tp'] for r in summary if r['task']['branch']=='shadow-FedAvg')
eligible=[n for n in candidates if all(totals[n][k]==0 for k in ('never','clean_scheduled','quorum_failures'))]
selected=max(eligible,key=lambda n:(totals[n]['shadow_tp'],-candidates.index(n))) if eligible else 'baseline'
result={'profile':'geometry-development-comparison-v1','totals':totals,'cases':summary,'selected':selected,
    'eligible':eligible,'selection_succeeded':bool(eligible),'qualification':'Development selection only; not fresh validation. Training/evaluation labels never enter clean geometry fitting.'}
save(lab/'development-comparison.json',result);(out/'development-comparison.json').write_bytes((lab/'development-comparison.json').read_bytes())
print('DEVELOPMENT RESULT',json.dumps({'totals':totals,'selected':selected,'eligible':eligible}),flush=True)
