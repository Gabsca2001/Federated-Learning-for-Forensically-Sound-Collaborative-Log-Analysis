"""Evaluate two prespecified ToN-IoT views with one frozen Data24 model."""
from pathlib import Path
from collections import Counter
import datetime as dt,hashlib,json
import numpy as np
import torch
from sklearn.metrics import roc_auc_score,average_precision_score
from fl_forensics.external_generalization import _model_from_export
from fl_forensics.preprocessing import FEATURE_NAMES

O=Path(__file__).resolve().parent
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')

def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n')

def binary_metrics(actual,predicted,scores=None):
    actual=np.asarray(actual,dtype=bool);predicted=np.asarray(predicted,dtype=bool)
    tn=int((~actual & ~predicted).sum());fp=int((~actual & predicted).sum())
    fn=int((actual & ~predicted).sum());tp=int((actual & predicted).sum())
    precision=tp/(tp+fp) if tp+fp else None
    recall=tp/(tp+fn) if tp+fn else None
    specificity=tn/(tn+fp) if tn+fp else None
    result=dict(rows=len(actual),confusion_matrix=dict(labels=['benign','attack'],values=[[tn,fp],[fn,tp]]),
                accuracy=(tn+tp)/len(actual) if len(actual) else None,attack_precision=precision,attack_recall=recall,
                attack_f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,benign_specificity=specificity,
                false_positive_rate=fp/(tn+fp) if tn+fp else None,
                balanced_accuracy=(recall+specificity)/2 if recall is not None and specificity is not None else None)
    if scores is not None:
        result.update(auroc=float(roc_auc_score(actual,scores)) if tp+fn and tn+fp else None,
                      average_precision=float(average_precision_score(actual,scores)) if tp+fn and tn+fp else None,
                      score='1 - frozen six-class benign softmax probability; threshold-free diagnostics only')
    return result


def main():
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    protocol_path=O/'protocol-before-source-processing.json';protocol=json.loads(protocol_path.read_text())
    plan_path=O/'evaluation-plan-before-inference.json';plan=json.loads(plan_path.read_text())
    assert plan['evaluator_sha256']==sha(Path(__file__)) and plan['protocol_sha256']==sha(protocol_path)
    assert sha(O/'frozen-model.json')==protocol['selected_model_sha256']
    assert sha(O/'frozen-scaler.json')==protocol['scaler_sha256']
    prepared=json.loads((O/'windows/preparation-summary.json').read_text())
    assert prepared['status']=='windows_and_duplicate_sensitivity_prepared' and prepared['protocol_sha256']==sha(protocol_path)
    model_export=json.loads((O/'frozen-model.json').read_text());scaler=json.loads((O/'frozen-scaler.json').read_text())
    assert scaler['feature_names']==FEATURE_NAMES
    classes=model_export['class_names'];benign=classes.index('benign')
    model=_model_from_export(model_export,np=np,torch=torch);model.eval()
    mean=np.asarray(scaler['mean']);scale=np.asarray(scaler['scale'])
    assert np.isfinite(mean).all() and np.isfinite(scale).all() and (scale>0).all()
    results={};predictions={}
    evaluated_utc=dt.datetime.now(dt.timezone.utc).isoformat()
    def infer(features):
        values=[]
        with torch.no_grad():
            for offset in range(0,len(features),1024):
                tensor=torch.from_numpy(np.asarray(features[offset:offset+1024],dtype=np.float32))
                values.append(torch.softmax(model(tensor),dim=1).numpy())
        probability=np.concatenate(values)
        assert np.isfinite(probability).all()
        return probability
    partition_path=R/'artifacts/m3-data24-parquet-iid-local-test-v1/manifest.json'
    assert sha(partition_path)==protocol['partition_manifest_sha256']
    partition=json.loads(partition_path.read_text());source=partition['server_evaluation_splits']['test']
    source_path=partition_path.parent/source['path']
    assert sha(source_path)==plan['Data24_test_sha256']==source['sha256']
    source_data=json.loads(source_path.read_text());source_rows=source_data['rows']['test']
    source_probability=infer(np.asarray([r['features'] for r in source_rows]))
    source_actual=np.asarray([r['label']!='benign' for r in source_rows]);source_predicted=source_probability.argmax(axis=1)!=benign
    control=binary_metrics(source_actual,source_predicted,1.-source_probability[:,benign])
    for name,key in [('occurrence','primary'),('exact-projection','sensitivity')]:
        path=O/'windows'/(name+'-windows.json');assert sha(path)==prepared[key]['sha256']
        dataset=json.loads(path.read_text());assert dataset['feature_names']==FEATURE_NAMES
        rows=dataset['rows'];raw=np.asarray([r['features'] for r in rows],dtype=np.float64)
        scaled=(raw-mean)/scale;assert np.isfinite(scaled).all()
        probability=infer(scaled);ids=probability.argmax(axis=1)
        actual=np.asarray([r['label']!='benign' for r in rows]);predicted=ids!=benign
        scores=1.-probability[:,benign]
        metrics=binary_metrics(actual,predicted,scores)
        daily={}
        for day in sorted({r['capture_id'] for r in rows}):
            select=np.asarray([r['capture_id']==day for r in rows])
            daily[day]=binary_metrics(actual[select],predicted[select],scores[select])
        feature_shift=[]
        for column,feature in enumerate(FEATURE_NAMES):
            feature_shift.append(dict(feature=feature,raw_quantiles_0_50_95_99_100=np.quantile(raw[:,column],[0,.5,.95,.99,1]).tolist(),
                                      scaled_mean=float(scaled[:,column].mean()),scaled_std=float(scaled[:,column].std()),
                                      absolute_z_gt5_fraction=float((np.abs(scaled[:,column])>5).mean())))
        result=dict(profile=name,metrics=metrics,per_day=daily,source_records=sum(r['source_record_count'] for r in rows),
                    predicted_model_class_counts=dict(Counter(classes[i] for i in ids)),
                    feature_shift=dict(any_absolute_z_gt3_fraction=float((np.abs(scaled)>3).any(axis=1).mean()),
                                       any_absolute_z_gt5_fraction=float((np.abs(scaled)>5).any(axis=1).mean()),features=feature_shift),
                    constant_attack_baseline=binary_metrics(actual,np.ones(len(rows),dtype=bool)),
                    constant_benign_baseline=binary_metrics(actual,np.zeros(len(rows),dtype=bool)),
                    no_new_threshold=True,no_scaler_fit=True,no_model_fit=True,window_dataset_sha256=sha(path))
        records=[]
        for row,truth,prediction,index,score in zip(rows,actual,predicted,ids,scores,strict=True):
            records.append(dict(window_id=row['window_id'],bucket=row['window_start_epoch']//60,capture_id=row['capture_id'],
                                actual_binary_label=int(truth),predicted_binary_label=int(prediction),predicted_model_label=classes[index],
                                attack_score=float(score),source_record_count=row['source_record_count']))
        save(O/(name+'-predictions.json'),records)
        predictions[name]=records;results[name]=result
    left=predictions['occurrence'];right=predictions['exact-projection']
    assert len(left)==len(right)
    assert all(a['bucket']==b['bucket'] and a['actual_binary_label']==b['actual_binary_label'] for a,b in zip(left,right,strict=True))
    summary=dict(status='frozen_transfer_complete',evaluated_utc=evaluated_utc,protocol_sha256=sha(protocol_path),
                 selected_model_sha256=protocol['selected_model_sha256'],scaler_sha256=protocol['scaler_sha256'],selected_round=protocol['selected_round'],
                 same_checkpoint_as_old_Data22_publication=protocol['same_checkpoint_as_old_Data22_publication'],
                 results=results,paired_prediction_changes=sum(a['predicted_binary_label']!=b['predicted_binary_label'] for a,b in zip(left,right,strict=True)),
                 Data24_test_control=control,evaluation_plan_sha256=sha(plan_path),
                 duplicate_sensitivity_preserves_windows_and_binary_truth=True,model_retrained=False,manuscript_changed=False,
                 limitations=['The rows are correlated one-minute windows from ten source dates, not independent population trials.',
                              'Exact projection groups are not verified physical-connection identities.',
                              'No attack-type to MITRE multiclass equivalence is asserted.',
                              'This locally verified model is not byte-identical to the checkpoint hash in the older Data22 publication.',
                              'Independent ToN-IoT retraining is a separate pending experiment.'])
    save(O/'transfer-results.json',summary)
    print(json.dumps(dict(status=summary['status'],primary=results['occurrence']['metrics'],sensitivity=results['exact-projection']['metrics'],paired_prediction_changes=summary['paired_prediction_changes']),indent=2),flush=True)


if __name__=='__main__':main()
