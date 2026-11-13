"""Recompute predictions through the established inference function and check totals."""
from pathlib import Path
import hashlib,json,math
import numpy as np
import torch
from fl_forensics.external_generalization import _predict,_binary_metrics
from fl_forensics.preprocessing import FEATURE_NAMES

O=Path(__file__).resolve().parent
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def main():
    torch.set_num_threads(1)
    result=json.loads((O/'transfer-results.json').read_text())
    protocol=json.loads((O/'protocol-before-source-processing.json').read_text())
    assert result['protocol_sha256']==sha(O/'protocol-before-source-processing.json')
    assert sha(O/'frozen-model.json')==result['selected_model_sha256']==protocol['selected_model_sha256']
    assert sha(O/'frozen-scaler.json')==result['scaler_sha256']==protocol['scaler_sha256']
    model=json.loads((O/'frozen-model.json').read_text());scaler=json.loads((O/'frozen-scaler.json').read_text())
    checks=[]
    for profile in ('occurrence','exact-projection'):
        path=O/'windows'/(profile+'-windows.json')
        assert sha(path)==result['results'][profile]['window_dataset_sha256']
        dataset=json.loads(path.read_text());rows=dataset['rows'];assert dataset['feature_names']==FEATURE_NAMES
        for row in rows:
            f=row['features'];n=row['source_record_count']
            assert len(f)==25 and all(math.isfinite(x) and x>=0 for x in f)
            assert f[0]==n==sum(row['binary_record_counts'].values())==sum(row['source_file_counts'].values())
            assert f[1]<=n and f[2]<=n and f[3]<=f[5]+1e-10
            assert all(0<=x<=1 for x in f[10:])
            assert all(abs(sum(f[a:b])-1)<=6e-12 for a,b in ((10,14),(14,19),(19,25)))
            assert row['label']==('attack' if row['binary_record_counts'].get('1',0) else 'benign')
            assert row['window_start_epoch']%60==0
        raw=np.asarray([r['features'] for r in rows]);scaled=(raw-np.asarray(scaler['mean']))/np.asarray(scaler['scale'])
        indices,_=_predict(model_export=model,features=scaled,batch_size=257,np=np,torch=torch)
        predictions=json.loads((O/(profile+'-predictions.json')).read_text())
        assert len(predictions)==len(rows)
        for row,prediction,index in zip(rows,predictions,indices,strict=True):
            assert row['window_id']==prediction['window_id']
            assert model['class_names'][index]==prediction['predicted_model_label']
        metrics=_binary_metrics([r['label'] for r in rows],[model['class_names'][i] for i in indices],benign='benign')
        assert metrics['confusion_matrix']==result['results'][profile]['metrics']['confusion_matrix']
        assert metrics['balanced_accuracy']==result['results'][profile]['metrics']['balanced_accuracy']
        checks.append(dict(profile=profile,windows_checked=len(rows),all_feature_invariants_checked=True,
                           predictions_recomputed_with_established_function=True,batch_size=257,
                           all_model_classes_and_binary_confusions_match=True))
    source=json.loads((O/'source-window-verification.json').read_text());assert source['status']=='verified'
    summary=dict(status='verified',transfer_results_sha256=sha(O/'transfer-results.json'),profiles=checks,
                 independent_source_window_spot_checks=source['checked_windows'],source_records_in_spot_checks=source['checked_source_records'],
                 full_source_rebuild=False,reference_checkpoint_verification=json.loads((O/'reference-campaign-verification.json').read_text())['status'],
                 new_TPM_attestation_performed=False,physical_connection_identity_proved=False,
                 qualification='All predictions freshly recomputed; full-source byte/count checks and bounded source-feature rebuild are separate evidence scopes.')
    (O/'verification.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2),flush=True)


if __name__=='__main__':main()
