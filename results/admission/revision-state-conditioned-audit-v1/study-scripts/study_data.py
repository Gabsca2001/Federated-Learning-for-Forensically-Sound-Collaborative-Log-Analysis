"""Generate training campaigns; export only server-visible model observations."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import numpy as np
from revision_dba_experiment import read_pinned,save,model_with_arrays,authenticate,signature,environment
from fl_forensics.canonical import digest_object,sha256_file,sha256_bytes
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.federated_model import dependencies,arrays_from_export,train_local,export_state
from fl_forensics.secure_round import _model_from_export
from fl_forensics.byzantine import aggregate_deltas,apply_delta,model_delta
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,poison_local_rows


def read(path): return json.loads(Path(path).read_bytes())
def flat(arrays): return np.concatenate([a.astype(np.float64).reshape(-1) for a in arrays])


def load_observation(workspace, limit=10):
    states=[]; changes=[]; anchors=[]; source=[]
    for path in sorted((Path(workspace)/'rounds').glob('round-*'))[:limit]:
        record=read(path/'round.json'); base=read(path/'base-model.json')
        values=arrays_from_export(base,np=np); clients=record['client_ids']
        local=[arrays_from_export(read(path/'updates'/f'{c}.json'),np=np) for c in clients]
        states.append(flat(values));changes.append(np.stack([flat(model_delta(values,m)) for m in local]))
        anchors.append(base);source.append({'base_model_sha256':sha256_file(path/'base-model.json'),
            'local_model_sha256':[sha256_file(path/'updates'/f'{c}.json') for c in clients]})
    return {'states':np.stack(states),'updates':np.stack(changes),'clients':clients,
        'sizes':[a.size for a in values],'anchors':anchors,'source':source}


def export_observation(path, observation):
    path=Path(path);path.mkdir(parents=True,exist_ok=False)
    np.savez_compressed(path/'observations.npz',states=observation['states'],updates=observation['updates'])
    save(path/'metadata.json',{'profile':'server-model-observations-v1','clients':observation['clients'],
        'sizes':observation['sizes'],'frames':len(observation['states']),
        'observations_sha256':sha256_file(path/'observations.npz'),
        'source_commitments':observation.get('source',[]),
        'includes_raw_client_rows':False,'includes_attack_labels':False})


def get_observation(path):
    path=Path(path);meta=read(path/'metadata.json')
    assert sha256_file(path/'observations.npz')==meta['observations_sha256']
    with np.load(path/'observations.npz',allow_pickle=False) as arrays:
        return {**meta,'states':arrays['states'],'updates':arrays['updates']}


class Generator:
    def __init__(self,partition_workspace,base_cfg):
        self.root=Path(partition_workspace);self.cfg=base_cfg
        self.partition=read(self.root/'manifest.json')
        self.records={r['client_id']:r for r in self.partition['clients']};self.clients=sorted(self.records)
        self.rows={c:read_pinned(self.root/r['dataset_path'],r['dataset_sha256'])['rows']['train'] for c,r in self.records.items()}
        ids=[r['window_id'] for rows in self.rows.values() for r in rows]
        assert len(ids)==len(set(ids))
        self.initial=read_pinned(base_cfg['base_model_path'],base_cfg['base_model_sha256'])
        assert self.initial['class_names']==self.partition['class_names']
        self.weights={c:float(self.partition['global_class_weights'][c]) for c in self.initial['class_names']}
        self.deps=dependencies();self.torch=self.deps[1];self.torch.set_num_threads(1);self.torch.use_deterministic_algorithms(True)

    def execute(self,base,seed,number,plan=None):
        models=[];counts=[];records=[];exports=[]
        for client in self.clients:
            rows=self.rows[client]
            if plan is not None:
                rows,_=poison_local_rows(rows=rows,plan=plan,client_id=client,round_number=number,distributed=True)
            model=_model_from_export(base,torch=self.torch,np=np)
            local_seed=seed+number*10000+int(self.records[client]['partition_id'])
            train_local(model=model,rows=rows,class_names=base['class_names'],class_weights=self.weights,
                epochs=self.cfg['local_epochs'],batch_size=self.cfg['batch_size'],learning_rate=self.cfg['learning_rate'],
                seed=local_seed,device_name='cpu',torch=self.torch,np=np)
            local=export_state(model,architecture=base['architecture'],class_names=base['class_names'])
            exports.append(local);models.append(arrays_from_export(local,np=np));counts.append(len(rows))
            records.append({'client_id':client,'seed':local_seed,'snapshot_sha256':self.records[client]['dataset_sha256'],
                'executed_rows_sha256':sha256_bytes(derived_json_bytes(rows))})
        values=arrays_from_export(base,np=np);deltas=[model_delta(values,m) for m in models]
        result=model_with_arrays(base,apply_delta(values,aggregate_deltas(deltas,strategy='fedavg',f=0,weights=counts)))
        return result,deltas,exports,records

    def campaign(self,output,seed,attackers=None):
        output=Path(output);assert not output.exists()
        plan=DistributedBackdoorPlan.model_validate({**self.cfg['attack_plan'],'seed':seed,
            'client_components':{c:[feature] for c,feature in zip(attackers,(13,17,24),strict=True)}}) if attackers else None
        save(output/'generation-protocol.json',{'profile':'software-state-conditioned-campaign-v1','seed':seed,
            'rounds':10,'partition_sha256':sha256_file(self.root/'manifest.json'),'initial_model_sha256':self.cfg['base_model_sha256'],
            'attack_plan_for_generation_and_evaluation_only':plan.model_dump(mode='json') if plan else None,
            'environment':environment(),'raw_rows_exported_to_detector':False})
        base=self.initial
        for number in range(1,11):
            prefix=output/'rounds'/f'round-{number:03d}'
            save(prefix/'base-model.json',base)
            result,deltas,exports,records=self.execute(base,seed,number,plan)
            for client,local,record in zip(self.clients,exports,records,strict=True):
                save(prefix/'updates'/f'{client}.json',local);record['local_model_sha256']=sha256_file(prefix/'updates'/f'{client}.json')
            save(prefix/'global-model.json',result)
            save(prefix/'round.json',{'round_number':number,'client_ids':self.clients,
                'base_model_sha256':sha256_file(prefix/'base-model.json'),'global_model_sha256':sha256_file(prefix/'global-model.json'),
                'local_training_records':records})
            base=result
            print(json.dumps({'campaign':output.name,'round':number}),flush=True)
        self.close(output)
        return load_observation(output)

    def stress(self,output,anchors,count,seed):
        output=Path(output);assert not output.exists()
        arrays=[arrays_from_export(base,np=np) for base in anchors]
        # Scale each perturbation solely from clean adjacent checkpoint changes.
        scales=[float(np.quantile([np.linalg.norm(arrays[i][k].astype(np.float64)-arrays[i-1][k]) for i in range(1,len(arrays))],.9)) for k in range(len(arrays[0]))]
        save(output/'generation-protocol.json',{'profile':'clean-server-state-stress-bank-v1','count':count,'seed':seed,
            'clean_anchor_sha256':[sha256_bytes(derived_json_bytes(a)) for a in anchors],
            'layer_perturbation_scales':scales,'norm_multipliers':[.5,1.,2.,4.],
            'rule':'Gaussian direction per parameter tensor, normalized to the clean q90 adjacent-checkpoint-change L2 times the fixed multiplier; no attack updates or labels are used.'})
        rng=np.random.default_rng(seed); states=[];updates=[];source=[]
        for index in range(count):
            anchor=anchors[index%len(anchors)];base_arrays=arrays[index%len(anchors)]
            perturbed=[]
            for tensor,scale in zip(base_arrays,scales,strict=True):
                noise=rng.normal(size=tensor.shape);norm=np.linalg.norm(noise)
                perturbed.append(tensor.astype(np.float64)+noise/max(norm,1e-12)*scale*(.5,1.,2.,4.)[index%4])
            base=model_with_arrays(anchor,perturbed)
            result,deltas,exports,records=self.execute(base,seed,index+1)
            prefix=output/f'context-{index:03d}';save(prefix/'base-model.json',base)
            for client,local in zip(self.clients,exports,strict=True):save(prefix/'updates'/f'{client}.json',local)
            save(prefix/'execution.json',records)
            states.append(flat(arrays_from_export(base,np=np)));updates.append(np.stack([flat(d) for d in deltas]))
            source.append({'base_model_sha256':sha256_file(prefix/'base-model.json'),
                'local_model_sha256':[sha256_file(prefix/'updates'/f'{c}.json') for c in self.clients]})
            if index%4==3:print(json.dumps({'stress_bank':output.name,'contexts':index+1}),flush=True)
        self.close(output)
        return {'states':np.stack(states),'updates':np.stack(updates),'clients':self.clients,
            'sizes':[a.size for a in arrays[0]],'anchors':[],'source':source}

    @staticmethod
    def close(output):
        signer=SoftwareECDSASigner.generate();(output/'experiment-authority.public.pem').write_bytes(signer.public_pem())
        core={'profile':'software-state-response-study-v1','artifacts':{p.relative_to(output).as_posix():sha256_file(p) for p in output.rglob('*') if p.is_file()},
            'fresh_TPM_attestation':False,'client_signatures_claimed':False}
        digest=digest_object(core);save(output/'manifest.json',{'core':core,'core_digest':digest,'signature':signature(signer,digest)})
        authenticate(output,sha256_file(output/'manifest.json'))
