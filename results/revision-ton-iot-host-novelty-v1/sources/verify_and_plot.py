"""Refit both detectors, recompute every decision and audit localization twice."""
from pathlib import Path
import json,datetime as dt,hashlib
import numpy as np
import torch
from threadpoolctl import threadpool_limits
from fl_forensics.federated_model import load_ndarrays
from fl_forensics.ton_iot_retraining import verify_checkpoint
from fl_forensics.ton_iot_novelty import calibrate_benign_threshold as installed_calibrate,minute_alert_support as installed_support
from novelty_rules import calibrate_benign_threshold,anomaly_flags,combine_flags
import run_host_novelty as run
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

O=Path(__file__).resolve().parent;D=O/'study';P=O.parent/'ton-iot-host-20261109'
def load(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2,allow_nan=False);f.write('\n')
def main():
    protocol=load(D/'protocol-before-detector-fitting.json');closure=load(D/'closure-before-test.json');results=load(D/'results.json')
    assert sha(O/'run_host_novelty.py')==protocol['runner_sha256'];assert sha(O/'novelty_rules.py')==protocol['rule_module_sha256']
    assert sha(D/'protocol-before-detector-fitting.json')==closure['protocol_sha256']==results['protocol_sha256']
    assert sha(D/'closure-before-test.json')==results['closure_sha256']
    data,chosen,spec,x=run.prepare();assert chosen.tolist()==protocol['benign_training_indices'];assert spec==load(D/'benign-transform.json')
    assert len(chosen)==10000 and not data['train']['y'][chosen].any()
    refit_scores={};baseline={};calibrations={}
    for kind in run.DETECTORS:
        model=run.detector(kind);model.fit(x['train'][chosen])
        for role in ('validation','test'):
            scores=run.score(model,kind,x[role]);refit_scores[(kind,role)]=scores
            with np.load(D/(kind+'-'+role+'.npz'),allow_pickle=False) as saved:
                np.testing.assert_array_equal(scores,saved['score']);np.testing.assert_array_equal(data[role]['y'],saved['actual']);np.testing.assert_array_equal(data[role]['bucket'],saved['bucket']);np.testing.assert_array_equal(data[role]['family'],saved['family'])
        for budget in run.BUDGETS:
            normal=refit_scores[(kind,'validation')][data['validation']['y']==0]
            fitted=calibrate_benign_threshold(normal,budget);assert installed_calibrate(normal,budget)==fitted
            calibrations[(kind,budget)]=fitted
    for entry in protocol['baseline_models']:
        model=run.parent.net(entry['seed']);arrays=verify_checkpoint(P/'study'/entry['id']/'selected.npz',entry['tensor_sha256']);load_ndarrays(model,arrays,torch=torch,np=np)
        for role in ('validation','test'):
            path=P/'study'/(entry['id']+'-'+role+'.npz');assert sha(path)==protocol['baseline_score_hashes'][entry['id']][role]
            with np.load(path,allow_pickle=False) as saved:expected=saved['score']
            actual=run.parent.scores(model,data[role]['x']);np.testing.assert_array_equal(actual,expected)
            baseline[(entry['id'],role)]=anomaly_flags(actual,entry['threshold'])
    localization_sets=0
    for entry in results['results']:
        if entry['kind']!='classifier':assert entry['calibration']==calibrations[(entry['detector'],entry['budget'])]
        for role in ('validation','test'):
            if entry['kind']=='classifier':pred=baseline[(entry['parent_id'],role)]
            else:
                novelty=anomaly_flags(refit_scores[(entry['detector'],role)],entry['calibration']['threshold'])
                pred=novelty if entry['kind']=='standalone' else combine_flags(baseline[(entry['parent_id'],role)],novelty)
            assert run.evaluate(data[role],pred)==entry[role]
            support=installed_support(data[role]['bucket'],data[role]['y'],pred)
            for name,counts in entry[role]['localization'].items():
                indices=np.flatnonzero(data[role]['common_family']==name)
                any_alert=attacked=benign_only=0
                for index in indices:
                    bucket=data[role]['common_bucket'][index];ix=data[role]['bucket']==bucket
                    a=bool(pred[ix].any());s=bool((pred[ix]&(data[role]['y'][ix]==1)).any())
                    any_alert+=a;attacked+=s;benign_only+=a and not s
                assert len(indices)==counts['attack_minutes'] and any_alert==counts['any_host_alert_minutes']
                assert attacked==counts['attacked_host_alert_minutes'] and benign_only==counts['benign_host_only_alert_minutes']
                assert int(support['attacked_host_alert'][indices].sum())==attacked
                localization_sets+=1
            if role=='test':
                with np.load(D/(entry['id']+'-decisions.npz'),allow_pickle=False) as saved:np.testing.assert_array_equal(pred,saved['predicted'])
                if entry['kind']=='combined':
                    extra=pred&~baseline[(entry['parent_id'],role)]
                    assert int((extra&(data[role]['y']==1)).sum())==entry['additional_native_true_positives']
                    assert int((extra&(data[role]['y']==0)).sum())==entry['additional_native_false_positives']
                    assert int((extra&(data[role]['family']=='mitm')).sum())==entry['additional_mitm_native_detections']
    means={kind:float(np.mean([e['validation']['native']['macro_f1'] for e in results['results'] if e['kind']=='combined' and e['detector']==kind and e['budget']==.01])) for kind in run.DETECTORS}
    selected=max(run.DETECTORS,key=lambda k:(means[k],-run.DETECTORS.index(k)))
    assert means==closure['validation_primary_macro_f1'] and selected==closure['selected_primary_detector']==results['selected_primary_detector']
    summary={}
    groups=[('classifier',[e for e in results['results'] if e['kind']=='classifier'])]
    for kind in run.DETECTORS:
        for budget in run.BUDGETS:
            for mode in ('standalone','combined'):
                groups.append((f'{kind}-{mode}-{int(budget*100):02d}pct',[e for e in results['results'] if e['detector']==kind and e['budget']==budget and e['kind']==mode]))
    for name,entries in groups:
        summary[name]=dict(configurations=len(entries),native={key:float(np.mean([e['test']['native'][key] for e in entries])) for key in ('macro_f1','benign_f1','attack_f1','attack_recall','false_positive_rate')},
            common={key:float(np.mean([e['test']['common'][key] for e in entries])) for key in ('macro_f1','false_positive_rate')},
            mitm_native_detected=[e['test']['native']['attack_family_recall']['mitm']['detected'] for e in entries],
            mitm_attacked_host_supported_minutes=[e['test']['localization']['mitm']['attacked_host_alert_minutes'] for e in entries],
            mitm_benign_only_coincidences=[e['test']['localization']['mitm']['benign_host_only_alert_minutes'] for e in entries])
    save(O/'summary.json',dict(selected_primary_detector=selected,primary_budget=.01,groups=summary,default_changed=False))
    save(O/'verification.json',dict(status='verified',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),benign_only_training_and_scaler_recomputed=True,
        anomaly_detectors_freshly_refitted=2,detector_validation_test_score_sets_exactly_matched=4,parent_classifier_models_freshly_loaded=3,parent_validation_test_score_sets_exactly_matched=6,
        configurations_recomputed=len(results['results']),native_and_common_validation_test_metric_sets_recomputed=4*len(results['results']),
        family_localization_metric_sets_checked_by_scalar_and_vectorized_methods=localization_sets,all_calibration_thresholds_refitted_from_validation_benign_only=True,
        method_selection_recomputed_from_validation_only=True,no_mitm_fit_or_calibration_examples=True,blind_test_claimed=False,default_changed=False))
    plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False})
    chosen_groups=['classifier','knn-standalone-01pct','knn-combined-01pct','isolation-combined-01pct','isolation-combined-05pct']
    labels=['Classifier','kNN alone 1%','Classifier + kNN 1%','Classifier + IF 1%','Classifier + IF 5%']
    fig,axes=plt.subplots(1,2,figsize=(12,4.8),layout='constrained')
    for i,name in enumerate(chosen_groups):
        q=summary[name];axes[0].bar(i-.17,q['native']['macro_f1'],width=.34,color='#2563eb',label='Macro-F1' if i==0 else None)
        axes[0].bar(i+.17,q['native']['false_positive_rate'],width=.34,color='#d97706',label='Benign FPR' if i==0 else None)
        detected=np.asarray(q['mitm_native_detected'])/130;axes[1].bar(i,float(detected.mean()),color='#0f766e')
        axes[1].scatter(np.full(len(detected),i),detected,color='#0f172a',s=12,zorder=3)
    for ax in axes:ax.set(xticks=np.arange(len(labels)),xticklabels=labels,ylim=(0,1.04));ax.tick_params(axis='x',rotation=35)
    axes[0].set_title('Native host/minute metrics (4,093 targets)');axes[0].legend(fontsize=8)
    axes[1].set(title='MITM detection on attacked host units (130)',ylabel='Recall')
    fig.suptitle('Exploratory benign-reference novelty | primary: classifier + '+selected+' at 1% calibration budget',fontsize=11)
    fig.savefig(O/'novelty-performance.png',dpi=180);plt.close(fig)
    fig,ax=plt.subplots(figsize=(9,4.5),layout='constrained')
    for i,name in enumerate(chosen_groups):
        q=summary[name];supported=float(np.mean(q['mitm_attacked_host_supported_minutes']));coincidence=float(np.mean(q['mitm_benign_only_coincidences']))
        ax.bar(i,supported,color='#0f766e',label='Attacked host alerted' if i==0 else None)
        ax.bar(i,coincidence,bottom=supported,color='#d97706',label='Only benign hosts alerted' if i==0 else None)
    ax.set(xticks=np.arange(len(labels)),xticklabels=labels,ylim=(0,102),ylabel='MITM minutes out of 102',title='An alert in an attacked minute can still miss the attacked host')
    ax.tick_params(axis='x',rotation=25);ax.legend(fontsize=8)
    fig.savefig(O/'novelty-localization.png',dpi=180);plt.close(fig)
    print(json.dumps(dict(verification=load(O/'verification.json'),summary=summary),indent=2),flush=True)
if __name__=='__main__':
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    with threadpool_limits(limits=1):main()
