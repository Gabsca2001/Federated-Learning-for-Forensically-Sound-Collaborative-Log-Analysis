from pathlib import Path
import json
import platform
import importlib.metadata
from audit_common import REPO,ROOT,LAB,OUT,METHODS,read,save,sha256_file

assert not LAB.exists();LAB.mkdir()
previous=OUT.parent/'geometry-detector-20261103'
assert sha256_file(previous/'completion-closure.json')=='17346b960336a5881a063c0026bfc9bc0241c2f16ae258a63e5632eb83680690'
for name,value in read(previous/'completion-closure.json')['core']['artifacts'].items():assert sha256_file(previous/name)==value
sources={}
for p in sorted((ROOT/'reports').glob('*.json')):
    r=read(p);case=p.stem
    sources[case]={'manifest_sha256':r['creation']['manifest_sha256'],'public_key_sha256':r['creation']['public_key_sha256'],
        'report_sha256':sha256_file(p),'rounds':15}
grad=REPO/'artifacts/revision-fedgradtrace-live-v1'
gradient={name:{'manifest_sha256':r['creation']['manifest_sha256'],'public_key_sha256':r['creation']['public_key_sha256']} for name,r in read(grad/'result.json')['runs'].items()}
protocol={'profile':'baseline-dba-validation-closure-v1','scope':'Consolidation and independent aggregation/inference replay; no client retraining, policy change, ToN-IoT acquisition or thesis edit.',
    'previous_completion_sha256':sha256_file(previous/'completion-closure.json'),'source_cases':sources,'gradient_cases':gradient,
    'fixed_test_report_sha256':sha256_file(ROOT/'fixed-endpoint-test.json'),
    'source_files':{p.relative_to(REPO).as_posix():sha256_file(p) for p in [REPO/'scripts/revision_dba_experiment.py',REPO/'src/fl_forensics/literature_baselines.py',REPO/'src/fl_forensics/byzantine.py',REPO/'src/fl_forensics/composite_admission.py']},
    'methods':METHODS,'reported_metrics':'Clean accuracy and six-class macro-F1; complete/component ASR; operational exclusions and downweights; false proposals relative to actual poisoned-row records. No client detector metric invented for nonselective aggregators.',
    'critical_boundaries':['Only FedAvg drives the nine source histories. Other method outputs are conditional on those common updates.',
        'The clean gated-composite source fits/calibrates on its own clean-round indicators; its clean false-positive rate is in-sample.',
        'WeiDetect keep_count=12 of 15 is fixed and prunes three clients even under all-clean inputs. Clipping is not exclusion.',
        'FedGradTrace is an adapted gradient aggregator, not a native malicious-client classifier; original 10% poison budget differs from DBA 50%.'],
    'benchmark':{'single_thread':True,'aggregation_kernel_contexts':'All 135 common-input contexts, three timed repetitions each; one warmup per method.',
        'kernel_inputs':'Preloaded arrays; model-to-delta conversion included where required. WeiDetect cached auxiliary F1; composite cached masses. No input-file loading or final evaluation.',
        'full_defense_contexts':'All nine source cases at rounds 1,10,15: 27 contexts; three timed repeats and one global warmup per method.',
        'full_defense_methods':['weidetect','gated_composite'],
        'full_defense_inputs':'Preloaded public server validation/auxiliary records and models. Include model instantiation/inference, scoring and aggregation; exclude local training, file loading, transport, TPM and reference-campaign generation.',
        'memory':'Separate process per method/scope. Linux process maximum RSS includes common application libraries, loaded inputs and allocator retention. It is not per-operation allocation or an incremental memory guarantee.',
        'gradient_cost':'Server aggregation of preserved actual gradient histories reported separately. No gradient acquisition time inferred from aggregation latency.'},
    'environment':{'python':platform.python_version(),'platform':platform.platform(),
        'versions':{n:importlib.metadata.version(n) for n in ('numpy','torch','scipy','scikit-learn','flwr')},
        'cpuinfo':next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name'))},
    'fresh_TPM_attestation':False,'new_client_training_calls':0,'production_code_changed':False,'new_test_selection_or_threshold_tuning':False}
save(LAB/'protocol-before-audit-and-benchmark.json',protocol)
print('BASELINE AUDIT AND BENCHMARK PROTOCOL FROZEN',flush=True)
