"""Resume only missing frozen assessment cases; preserve every completed artifact."""
import os
for name in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):os.environ[name]='1'
from pathlib import Path
import sys,json
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis');sys.path.insert(0,str(R/'scripts'))
import revision_episode_attribution as study
from episodic_attribution_groups import detect
from revision_study_data import read,Generator
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file
D=study.D;E=D/'source-evidence'

def main():
    p=read(D/'protocol-before-training.json');study.check(p);assert p==read(E/'protocol.json')
    assert not (E/'manifest.json').exists() and not (D/'source-closure.json').exists()
    c=read(D/'calibration-closure-before-assessment.json')
    assert sha256_file(E/'reference.json')==c['reference_sha256'] and sha256_file(E/'calibration.json')==c['calibration_sha256']
    pins={str(f.relative_to(E)):sha256_file(f) for f in E.rglob('*') if f.is_file()}
    complete=[];missing=[]
    for task in p['tasks']:
        folder=E/'histories'/task['alias'];paths=[folder/'result.json',folder/'last-checkpoint.json',E/'selection'/f"{task['alias']}.json"]
        if all(f.exists() for f in paths):
            result=read(paths[0]);assert result['task']==task and result['complete'] and len(result['journal'])==15
            assert study.prior.source.pilot.old_study.export_digest(read(paths[1]))==result['final_model_sha256']
            assert read(paths[2])['profile']=='separated-utility-magnitude-episodes-v5';complete.append(task['alias'])
        else:
            assert not any(f.exists() for f in paths),'Partial case needs a separate audit, not overwriting'
            missing.append(task['alias'])
    save(D/'resume-definition-before-completion.json',dict(resumer_sha256=sha256_file(Path(__file__)),
        completed_cases=complete,missing_cases=missing,preserved_source_files=pins,
        interruption='No running process or numerical exception found; external interruption cause unknown.',
        numerical_protocol_changed=False))
    engine=study.Engine(p,write=True);ref=read(E/'reference.json');cal=read(E/'calibration.json')
    for task in p['tasks']:
        if task['alias'] not in missing:continue
        result,model,obs=engine.history(task,[],True);selection=detect(obs,ref,cal)
        save(E/'histories'/task['alias']/'result.json',result);save(E/'histories'/task['alias']/'last-checkpoint.json',model)
        save(E/'selection'/f"{task['alias']}.json",selection)
        print(json.dumps(dict(resumed_case=task['alias'],selected_group=selection['selected_group'])),flush=True)
    assert all(sha256_file(E/n)==h for n,h in pins.items())
    selected=[]
    for task in p['tasks']:
        v=read(E/'selection'/f"{task['alias']}.json")
        selected.append(dict(alias=task['alias'],individual_anomalies=v['individual_anomalies'],selected_group=v['selected_group']))
    save(E/'selection-before-membership-and-effects.json',dict(cases=selected,labels_read_by_detector=False,
        attack_outcomes_read_by_detector=False,future_frames_read_by_detector=False,not_process_isolated_blinding=True))
    study.check(p);Generator.close(E);save(D/'source-closure.json',dict(manifest_sha256=sha256_file(E/'manifest.json')))
    save(D/'resume-completion.json',dict(preserved_source_files_unchanged=True,preserved_file_count=len(pins),
        resumed_cases=missing,completed_cases=len(p['tasks']),numerical_protocol_changed=False))
    print(json.dumps(read(D/'resume-completion.json'),indent=2),flush=True)

if __name__=='__main__':main()
