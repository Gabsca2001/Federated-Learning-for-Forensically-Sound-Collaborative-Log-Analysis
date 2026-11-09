"""Verify all selected predictions and checkpoint chains; replay one primary history."""
from pathlib import Path
import hashlib,json,math,time
import numpy as np
import torch
from sklearn.metrics import f1_score
from flwr.server.strategy.aggregate import aggregate
from fl_forensics.federated_model import (build_model,seed_everything,model_to_ndarrays,load_ndarrays,train_local,export_state,architecture_record)
from fl_forensics.external_generalization import _predict
from fl_forensics.ton_iot_retraining import tensor_digest,verify_checkpoint,select_round,binary_metrics

O=Path(__file__).resolve().parent;W=O/'study'
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def load(path):return json.loads(path.read_text())
def new(seed):
    seed_everything(seed,torch=torch,np=np)
    return build_model(input_features=25,class_count=2,hidden_layers=[128,64],embedding_size=32,dropout=0.,torch=torch)


def main():
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    protocol=load(W/'protocol-before-training.json');closure=load(W/'training-closure-before-test.json');results=load(W/'target-test-results.json')
    assert closure['protocol_sha256']==results['protocol_sha256']==sha(W/'protocol-before-training.json')
    assert results['training_closure_sha256']==sha(W/'training-closure-before-test.json')
    assert len(closure['selections'])==18
    split=load(W/'split-and-partition.json');assert sha(W/'split-and-partition.json')==protocol['split_partition_sha256']
    checked=0;models_checked=0
    architecture=architecture_record(input_features=25,class_count=2,hidden_layers=[128,64],embedding_size=32,dropout=0.)
    by_id={r['run_id']:r for r in results['results']}
    for entry in closure['selections']:
        directory=W/'runs'/entry['run_id']
        assert sha(directory/'history.json')==entry['history_sha256']
        assert sha(directory/'selection.json')==entry['selection_sha256']
        history=load(directory/'history.json');previous='0'*64
        for number,record in enumerate(history,1):
            assert record['round']==number and record['previous_round_sha256']==previous
            core={k:v for k,v in record.items() if k!='round_sha256'}
            previous=hashlib.sha256(json.dumps(core,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            assert previous==record['round_sha256'] and len(record['client_updates'])==15
            assert sum(u['examples'] for u in record['client_updates'])==protocol['train_rows']
            path=directory/'checkpoints'/f'round-{number:03d}.npz'
            assert sha(path)==record['checkpoint_sha256'];verify_checkpoint(path,record['tensor_sha256']);models_checked+=1
        if entry['status']!='trained':continue
        assert len(history)==30 and select_round(history)['round']==entry['selected_round']
        checkpoint=directory/'checkpoints'/f'round-{entry["selected_round"]:03d}.npz'
        model=new(entry['seed']);load_ndarrays(model,verify_checkpoint(checkpoint,entry['tensor_sha256']),torch=torch,np=np)
        key=entry['view']+'-'+entry['mode'];path=W/'prepared'/key/'test.npz'
        assert sha(path)==protocol['prepared_inputs'][key]['test.npz']
        with np.load(path,allow_pickle=False) as data:x,y=data['x'],data['y']
        exported=export_state(model,architecture=architecture,class_names=['benign','attack'])
        ids,confidence=_predict(model_export=exported,features=x,batch_size=257,np=np,torch=torch)
        with np.load(directory/'test-predictions.npz',allow_pickle=False) as predictions:
            assert np.array_equal(y,predictions['actual']) and np.array_equal(ids,predictions['predicted'])
            recomputed=np.where(np.asarray(ids)==1,confidence,1.-np.asarray(confidence))
            assert np.allclose(recomputed,predictions['attack_score'],atol=2e-6,rtol=2e-5)
        assert binary_metrics(y,ids)['confusion_matrix']==by_id[entry['run_id']]['test']['confusion_matrix']
        checked+=1
    transfer=O.parent/'ton-iot-transfer-20261109'
    previous=load(transfer/'transfer-results.json')
    assert sha(transfer/'transfer-results.json')==protocol['prior_transfer_results_sha256']
    assert sha(transfer/'frozen-model.json')==previous['selected_model_sha256']
    assert sha(transfer/'frozen-scaler.json')==protocol['source_scaler_sha256']
    source_model=load(transfer/'frozen-model.json');source_scaler=load(transfer/'frozen-scaler.json')
    for baseline in results['frozen_source_baselines']:
        view=baseline['view'];path=transfer/'windows'/(view+'-windows.json')
        assert sha(path)==protocol['input_dataset_sha256'][view]
        source_rows=[r for r in load(path)['rows'] if r['capture_id']=='2019-04-29']
        raw=np.asarray([r['features'] for r in source_rows],dtype=np.float64)
        scaled=(raw-np.asarray(source_scaler['mean']))/np.asarray(source_scaler['scale'])
        indices,_=_predict(model_export=source_model,features=scaled,batch_size=257,np=np,torch=torch)
        metrics=binary_metrics([int(r['label']=='attack') for r in source_rows],
                               [int(source_model['class_names'][i]!='benign') for i in indices])
        assert metrics['confusion_matrix']==baseline['test']['confusion_matrix']
    # A fresh deterministic replay checks the actual training trajectory, not just stored hashes.
    run_id='occurrence-target-standard-s341593';entry=next(r for r in closure['selections'] if r['run_id']==run_id)
    assert entry['status']=='trained'
    history=load(W/'runs'/run_id/'history.json')
    with np.load(W/'prepared/occurrence-target-standard/train-validation.npz',allow_pickle=False) as data:
        x_train,y_train,x_validation,y_validation=data['x_train'],data['y_train'],data['x_validation'],data['y_validation']
    rows=[dict(features=x.tolist(),label='attack' if y else 'benign') for x,y in zip(x_train,y_train,strict=True)]
    model=new(341593);started=time.monotonic();client_checks=0
    for number,expected in enumerate(history,1):
        base=model_to_ndarrays(model,np=np);updates=[]
        for client,indices in enumerate(split['train_indices_by_client']):
            local=new(341593);load_ndarrays(local,base,torch=torch,np=np)
            train_local(model=local,rows=[rows[i] for i in indices],class_names=['benign','attack'],class_weights=split['class_weights'],
                        epochs=2,batch_size=128,learning_rate=.001,seed=341593+number*10000+client,device_name='cpu',torch=torch,np=np)
            arrays=model_to_ndarrays(local,np=np)
            assert tensor_digest(arrays)==expected['client_updates'][client]['tensor_sha256']
            updates.append((arrays,len(indices)));client_checks+=1
        averaged=aggregate(updates);assert tensor_digest(averaged)==expected['tensor_sha256']
        load_ndarrays(model,averaged,torch=torch,np=np);model.eval()
        with torch.no_grad():ids=model(torch.from_numpy(x_validation)).argmax(dim=1).numpy()
        metric=float(f1_score(y_validation,ids,labels=[0,1],average='macro',zero_division=0))
        assert metric==expected['validation_macro_f1']
    verification=dict(status='verified',test_results_sha256=sha(W/'target-test-results.json'),
                       selected_predictions_recomputed=checked,global_checkpoints_checked=models_checked,
                       replayed_run=run_id,replayed_rounds=30,replayed_local_updates=client_checks,
                       replay_tensor_matches=30,validation_selection_metrics_recomputed=30,replay_seconds=time.monotonic()-started,
                       frozen_source_test_baselines_recomputed=2,
                       all_18_training_histories_retrained=False,test_is_new_blind_population=False,
                       new_TPM_or_Byzantine_campaign=False,qualification='All stored checkpoint chains and selected predictions checked; one complete primary training trajectory freshly replayed.')
    (W/'verification.json').write_text(json.dumps(verification,indent=2)+'\n')
    print(json.dumps(verification,indent=2),flush=True)


if __name__=='__main__':main()
