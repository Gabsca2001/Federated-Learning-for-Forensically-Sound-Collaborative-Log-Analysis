"""Post-hoc failure diagnosis; never fit or alter a gate from reserved outcomes."""
from __future__ import annotations
import csv
import json
import shutil
from collections import Counter
from fractions import Fraction
from pathlib import Path
import os
import revision_severe_gate_study as study
from revision_study_data import read
from revision_dba_experiment import outcomes,save
from fl_forensics.canonical import sha256_file

LAB=study.LAB;ROOT=study.ROOT;OUT=LAB/'posthoc-diagnosis'
LOCAL=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'severe-gate-20261106')


def csvout(name,rows):
    with (OUT/name).open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(dict.fromkeys(k for r in rows for k in r)))
        writer.writeheader();writer.writerows(rows)


def main():
    assert not OUT.exists(),'Preserve completed diagnosis'
    protocol=read(LAB/'evaluation/protocol-before-training.json');study.assert_locks(protocol)
    audit=read(LAB/'evaluation/verified/summary.json');assert audit['status']=='verified' and audit['test_accessed']
    study.configure('evaluation');test=read(ROOT/'artifacts/m3-data24-parquet-iid-local-test-v1/server/splits/test.json')['rows']['test']
    study.base.POLICIES=(*study.ORIGINAL_POLICIES,'calibrated_gated','calibrated_sequential','calibrated_no_band')
    clients=[];clean_rounds=[];direct=[];bad_clean=[]
    for c in audit['cases']:
        task=c['task']
        if task['method']!='severe_gate' or task['mode']!='clean':continue
        manifest=read(LAB/'partitions'/str(task['seed'])/'manifest.json')
        assert sha256_file(LAB/'partitions'/str(task['seed'])/'manifest.json')==protocol['partitions'][str(task['seed'])]
        nominal=sum(r['train_row_count'] for r in manifest['clients'])
        records={r['client_id']:r for r in manifest['clients']}
        total_loss=Counter();q=Counter();d=Counter()
        for row in c['rows']:
            losses={i:Fraction(row['example_counts'][i])-Fraction(row['masses'][i]) for i in row['statuses']}
            for i,loss in losses.items():
                total_loss[i]+=loss;q[i]+=row['statuses'][i].endswith('quarantined');d[i]+=row['statuses'][i]=='accepted_downweighted'
            maximum=max(losses,key=losses.get)
            clean_rounds.append(dict(cohort=task['cohort'],seed=task['seed'],round=row['round'],
                retained_nominal_mass=float(1-sum(losses.values())/nominal),largest_lost_mass_client=maximum,
                largest_client_loss_fraction=float(losses[maximum]/nominal),
                largest_client_nominal_fraction=row['example_counts'][maximum]/nominal,
                largest_client_status=row['statuses'][maximum]))
        retention=float(1-sum(total_loss.values())/(nominal*len(c['rows'])))
        case_clients=[]
        for client,record in records.items():
            path=LAB/'partitions'/str(task['seed'])/record['dataset_path'];assert sha256_file(path)==record['dataset_sha256']
            labels=Counter(r['label'] for r in read(path)['rows']['train'])
            source=LAB/'evaluation/cases'/task['name']/'evidence/rounds/round-001/gate-state.json'
            profile=read(source)['reference_profiles'][client]
            entry=dict(cohort=task['cohort'],seed=task['seed'],client=client,examples=record['train_row_count'],
                nominal_fraction=record['train_row_count']/nominal,quarantined_rounds=q[client],downweighted_rounds=d[client],
                lost_nominal_mass_fraction=float(total_loss[client]/(nominal*len(c['rows']))),
                largest_class=max(labels,key=labels.get),largest_class_fraction=max(labels.values())/sum(labels.values()),
                labels=json.dumps(labels,sort_keys=True),initial_reference_profile=profile)
            clients.append(entry);case_clients.append(entry)
        minimum=min(r['retained_nominal_mass'] for r in clean_rounds if r['seed']==task['seed'])
        if retention<.90 or minimum<.80:
            leader=max(case_clients,key=lambda r:r['lost_nominal_mass_fraction'])
            bad_clean.append(dict(cohort=task['cohort'],seed=task['seed'],pooled_mass_retention=retention,
                minimum_round_mass_retention=minimum,largest_loss_client=leader))
    # Every attacked proposed history contributes one first-worst verified
    # checkpoint. This outcome-dependent selection is diagnostic, not reserved
    # validation of a newly tuned rule. Alternate methods use the SAME updates
    # and SAME parent checkpoint; no later local training is reconstructed here.
    for c in audit['cases']:
        task=c['task']
        if task['method']!='severe_gate' or task['mode']=='clean':continue
        peak=max(c['rows'],key=lambda r:(study.base.scalar_asr(r['test']),-r['round']))
        number=peak['round'];folder=LAB/'evaluation/cases'/task['name']/'evidence/rounds'/f'round-{number:03d}'
        initial=read(folder/'base-model.json');gen,validation,correct=study.context(protocol,task);gen.gate_round=number
        predicted,_=study.base.predict(gen.initial,test,gen.deps)
        correct_test=[a==r['label'] for a,r in zip(predicted,test,strict=True)]
        exports=[read(folder/'updates'/f'{i}.json') for i in gen.clients]
        state,arrays=study.gate_state(initial,exports,gen,study.base.settings_for(protocol),validation)
        stored=read(folder/'gate-state.json')
        assert {k:v for k,v in state.items() if k!='timing'}=={k:v for k,v in stored.items() if k!='timing'}
        mean_task={**task,'candidate':'mean_control','method':'mean_control'}
        mean_gen,_,_=study.context(protocol,mean_task);mean_gen.gate_round=number
        mean_state,_=study.gate_state(initial,exports,mean_gen,study.base.settings_for(protocol),validation)
        plan=study.base.make_plan(protocol,task);modified=set(peak['actually_manipulated_clients'])
        nominal=sum(len(gen.rows[i]) for i in gen.clients)
        for method,policy,used in (
            ('tpm_only','tpm_only',state),('gated_composite','gated_composite',state),
            ('mean_control','calibrated_gated',mean_state),('severe_gate','calibrated_gated',state)):
            model,masses,co=study.base.numerical(initial,arrays,gen,used,study.base.settings_for(protocol),policy)
            metrics=outcomes(model,test,plan,correct_test,gen.deps) if model is not None else None
            if method=='severe_gate':assert metrics==peak['test']
            decisions={i:used['decisions'][i][policy]['status'] for i in gen.clients}
            total=sum(masses.values());manip=sum(masses[i] for i in modified)
            direct.append(dict(cohort=task['cohort'],seed=task['seed'],mode=task['mode'],round=number,
                checkpoint_selection='first maximum proposed worst-trigger test ASR; post-hoc',
                same_input_alternate_method=method,defined=model is not None,
                source_parent_sha256=sha256_file(folder/'base-model.json'),
                actual_checkpoint_sha256=sha256_file(folder/'global-model.json'),
                alternate_model_sha256=study.base.digest(model) if model is not None else None,
                full_asr=metrics['complete_trigger']['asr'] if metrics else None,
                worst_trigger_asr=study.base.scalar_asr(metrics) if metrics else None,
                clean_macro_f1=metrics['clean']['macro_f1_all_model_classes'] if metrics else None,
                retained_nominal_mass=float(total/nominal),
                manipulated_coefficient_mass=float(manip/total) if total else None,
                unmodified_nominal_mass_lost=float(sum(Fraction(len(gen.rows[i]))-masses[i] for i in gen.clients if i not in modified)/nominal),
                unmodified_quarantined=sum(decisions[i].endswith('quarantined') for i in gen.clients if i not in modified),
                manipulated_quarantined=sum(decisions[i].endswith('quarantined') for i in modified),
                selected_alpha=peak['selected_alpha']))
        print(json.dumps(dict(diagnosed=task['name'],round=number)),flush=True)
    assert len(clients)==90 and len(clean_rounds)==90 and len(direct)==72
    OUT.mkdir();csvout('clean-client-exclusions.csv',clients);csvout('clean-round-retention.csv',clean_rounds)
    csvout('same-input-counterfactuals.csv',direct)
    summary=dict(profile='severe-gate-posthoc-failure-diagnosis-v1',status='verified',
        source_verification_sha256=sha256_file(LAB/'evaluation/verified/summary.json'),
        diagnostic_script_sha256=sha256_file(Path(__file__)),clean_clients=90,clean_rounds=90,
        direct_counterfactuals=72,clean_mass_failures=bad_clean,
        new_fitting_or_threshold_changes=False,posthoc=True,later_retraining=False,
        causal_scope='Direct one-round numerical alternatives on identical saved updates/parent only; not alternate multi-round trajectories.')
    save(OUT/'summary.json',summary);study.assert_locks(protocol)
    files={p.name:sha256_file(p) for p in OUT.iterdir() if p.is_file()};save(OUT/'inventory.json',dict(files=files))
    for path in OUT.iterdir():shutil.copy2(path,LOCAL/('diagnosis-'+path.name))
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
