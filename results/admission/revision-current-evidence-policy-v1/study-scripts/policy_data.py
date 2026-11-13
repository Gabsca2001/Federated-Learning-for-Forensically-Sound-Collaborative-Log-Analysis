"""Case-specific client training generator; raw rows never enter the worker."""
from pathlib import Path
import numpy as np
from study_data import Generator,read,export_observation,flat
from revision_dba_experiment import save,model_with_arrays
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.byzantine import aggregate_deltas,apply_delta,model_delta


def generate_clean(generator,output,seed,horizon=15):
    output=Path(output);assert not output.exists()
    save(output/'generation-protocol.json',{'profile':'clean-sequential-calibration-campaign-v1','seed':seed,
        'horizon':horizon,'partition_manifest_sha256':sha256_file(generator.root/'manifest.json'),
        'base_model_sha256':generator.cfg['base_model_sha256'],'raw_rows_exported':False})
    base=generator.initial;states=[];updates=[];commits=[]
    for number in range(1,horizon+1):
        prefix=output/'rounds'/f'round-{number:03d}';save(prefix/'base-model.json',base)
        result,deltas,exports,training=generator.execute(base,seed,number)
        for client,model,record in zip(generator.clients,exports,training,strict=True):
            save(prefix/'updates'/f'{client}.json',model);record['local_model_sha256']=sha256_file(prefix/'updates'/f'{client}.json')
        save(prefix/'global-model.json',result)
        save(prefix/'round.json',{'round':number,'clients':generator.clients,'base_model_sha256':sha256_file(prefix/'base-model.json'),
            'global_model_sha256':sha256_file(prefix/'global-model.json'),'training':training})
        states.append(flat(arrays_from_export(base,np=np)));updates.append(np.stack([flat(d) for d in deltas]))
        commits.append({'base_model_sha256':sha256_file(prefix/'base-model.json'),'local_model_sha256':[t['local_model_sha256'] for t in training]})
        base=result
        print({'calibration_campaign':output.name,'round':number},flush=True)
    generator.close(output)
    return {'states':np.stack(states),'updates':np.stack(updates),'clients':generator.clients,
        'sizes':[a.size for a in arrays_from_export(base,np=np)],'source':commits}


def current_observation(base,deltas,clients,source_commitment):
    values=arrays_from_export(base,np=np)
    return {'states':flat(values)[None,:],'updates':np.stack([flat(d) for d in deltas])[None,:,:],
        'clients':clients,'sizes':[a.size for a in values],'source':[source_commitment]}


def aggregate_selected(generator,base,exports,excluded):
    selected=[i for i,c in enumerate(generator.clients) if c not in excluded]
    if len(selected)<8:return None
    arrays=arrays_from_export(base,np=np)
    locals=[arrays_from_export(exports[i],np=np) for i in selected]
    counts=[len(generator.rows[generator.clients[i]]) for i in selected]
    return model_with_arrays(base,apply_delta(arrays,aggregate_deltas([model_delta(arrays,a) for a in locals],strategy='fedavg',f=0,weights=counts)))
