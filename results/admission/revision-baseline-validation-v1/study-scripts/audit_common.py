"""Shared read-only source readers and baseline cost/replay operations."""
from pathlib import Path
import json
import numpy as np
from revision_dba_experiment import (save,read_pinned,authenticate,model_with_arrays,evaluate,
    outcomes,predict,full_gradient)
from fl_forensics.canonical import sha256_file,sha256_bytes
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.federated_model import arrays_from_export,dependencies
from fl_forensics.byzantine import model_delta,apply_delta,aggregate_deltas,update_indicators
from fl_forensics.literature_baselines import flame_aggregate,weidetect_aggregate,fedgradtrace_global_gradient
from fl_forensics.composite_admission import (build_indicator_references,score_statistical_indicators,
    calibrate_policy_thresholds,decide_admission_policies)
from fl_forensics.composite_admission_models import TrustSignal

REPO=Path.cwd();LAB=REPO/'artifacts/revision-baseline-closure-v1';ROOT=REPO/'artifacts/revision-dba-three-seed-v1'
OUT=Path(__file__).parent
METHODS=('fedavg','coordinate_median','trimmed_mean','multikrum','bulyan','flame','weidetect','gated_composite')
def read(path):return json.loads(Path(path).read_bytes())

def load_case(case,number):
    workspace=ROOT/case;cfg=read(workspace/'protocol-before-training.json');p=workspace/'rounds'/f'round-{number:03d}'
    record=read(p/'round.json');comparison=read(p/'comparison.json');base=read(p/'base-model.json');clients=record['client_ids']
    exports=[read(p/'updates'/f'{c}.json') for c in clients];arrays=arrays_from_export(base,np=np)
    models=[arrays_from_export(m,np=np) for m in exports];counts=[r['train_row_count'] for r in sorted(read(Path(cfg['partition_workspace'])/'manifest.json')['clients'],key=lambda r:r['client_id'])]
    settings=read_yaml(cfg['composite_config_path'])
    clean_indicators=None if cfg.get('clean_reference_workspace') is None else read(Path(cfg['clean_reference_workspace'])/'rounds'/f'round-{number:03d}'/'indicators.json')
    return {'case':case,'number':number,'workspace':workspace,'prefix':p,'config':cfg,'record':record,
        'comparison':comparison,'base':base,'arrays':arrays,'exports':exports,'models':models,'clients':clients,
        'counts':counts,'calibration':read(p/'calibration-and-decisions.json'),'settings':settings,'clean_indicators':clean_indicators}

def kernel(method,d,*,wei_scores=None,masses=None):
    cfg=d['config'];arrays=d['arrays'];models=d['models'];clients=d['clients']
    if method in ('fedavg','coordinate_median','trimmed_mean','multikrum','bulyan'):
        return apply_delta(arrays,aggregate_deltas([model_delta(arrays,m) for m in models],strategy=method,
            f=0 if method=='fedavg' else cfg['declared_max_faulty_clients'],weights=d['counts'] if method=='fedavg' else None))
    if method=='flame':return flame_aggregate(base=arrays,models=models,client_ids=clients,noise_factor=.01,seed=cfg['seed']+d['number'])[0]
    if method=='weidetect':
        scores=wei_scores if wei_scores is not None else d['comparison']['comparisons']['weidetect']['aggregation']['validation_f1']
        return weidetect_aggregate(models=models,client_ids=clients,validation_f1=scores,keep_count=cfg['weidetect_keep_count'],seed=cfg['seed']+d['number'])[0]
    if method=='gated_composite':
        mass=masses if masses is not None else [r['mass'] for r in d['calibration']['decisions']]
        selected=[i for i,v in enumerate(mass) if v>0]
        if len(selected)<cfg['minimum_contributors']:return None
        from flwr.server.strategy.aggregate import aggregate
        return aggregate([(models[i],mass[i]) for i in selected])
    raise ValueError(method)

def validation_inputs(cfg):
    validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
    spec=read(ROOT/'clean-s341593/fixed-auxiliary-validation-set.json');by_id={r['window_id']:r for r in validation}
    auxiliary=[by_id[k] for k in spec['window_ids']]
    assert {r['label'] for r in auxiliary}==set(read(cfg['base_model_path'])['class_names'])
    return validation,auxiliary

def full_defense(method,d,deps,validation,auxiliary):
    if method=='weidetect':
        scores=[evaluate(m,auxiliary,deps)['macro_f1_all_model_classes'] for m in d['exports']]
        return kernel(method,d,wei_scores=scores),scores
    if method=='gated_composite':
        cfg=d['config'];indicators=update_indicators([model_delta(d['arrays'],m) for m in d['models']],client_ids=d['clients'])
        base_f1=evaluate(d['base'],validation,deps)['macro_f1_all_model_classes']
        for row,export in zip(indicators,d['exports'],strict=True):row['validation_impact']=base_f1-evaluate(export,validation,deps)['macro_f1_all_model_classes']
        settings=d['settings'];specs=settings['statistics']['indicators']
        directions={n:s['direction'] for n,s in specs.items()};weights={n:s['weight'] for n,s in specs.items()}
        clean_indicators=indicators if cfg.get('clean_reference_workspace') is None else d['clean_indicators']
        refs=build_indicator_references(clean_indicators,directions=directions)
        clean_scores=score_statistical_indicators(clean_indicators,references=refs,weights=weights,z_cap=settings['statistics']['robust_z_cap'])
        scored=score_statistical_indicators(indicators,references=refs,weights=weights,z_cap=settings['statistics']['robust_z_cap'])
        pc=settings['policies'];tc=pc['calibration']
        thresholds=calibrate_policy_thresholds(list(clean_scores.values()),trust_weight=pc['composite_trust_weight'],
            statistical_margin=tc['statistical_max_margin'],composite_margin=tc['composite_max_margin'],downweight_quantile=tc['composite_downweight_quantile'])
        trust=TrustSignal(raw_status='software-experiment-admissibility-assumption',admissible=True,risk=0,evaluated_checks=[],failed_checks=[],
            reasons=['All software experiment identities are assumed admissible. No fresh TPM attestation is claimed.'])
        mass=[];status=[]
        for client,count in zip(d['clients'],d['counts'],strict=True):
            dec=next(x for x in decide_admission_policies(trust=trust,statistics=scored[client],
                statistical_threshold=thresholds.statistical_threshold,composite_threshold=thresholds.composite_threshold,
                composite_downweight_threshold=thresholds.composite_downweight_threshold,trust_weight=thresholds.trust_weight) if x.policy=='gated_composite')
            mass.append(count*cfg['accepted_downweight_factor'] if dec.status=='accepted_downweighted' else float(count) if dec.contributes else 0.)
            status.append(dec.status)
        return kernel(method,d,masses=mass),{'masses':mass,'status':status}
    raise ValueError(method)

def read_yaml(path):
    import yaml
    return yaml.safe_load(Path(path).read_bytes())
