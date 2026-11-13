"""Predeclare a secondary common-input check with independent clean references."""
from audit_common import *

root=REPO/'artifacts/revision-geometry-detector-v1'
source=read(root/'reserved-execution-before-training.json')
cases=[t for t in source['tasks'] if t['branch']=='shadow-FedAvg']
assert len(cases)==12
protocol={'profile':'fixed-reference-secondary-baseline-comparison-v1',
    'status':'Secondary analysis of previously evaluated source trajectories; not a newly reserved prospective dataset.',
    'source_root':str(root),'source_closure_sha256':sha256_file(root/'study-artifact-closure.json'),
    'cases':cases,'methods':['fedavg','flame','weidetect','gated_fixed_reference','client_envelope'],
    'historical_clean_references':{'iid':'artifacts/revision-sequential-round-policy-v1/private-calibration/iid/cal-451593',
        'non-iid':'artifacts/revision-sequential-round-policy-v1/private-calibration/non-iid/cal-454593'},
    'reference_rule':'First predeclared historical clean calibration seed per matching cohort, same round index. Build original composite references/thresholds from this source, never from the evaluation cases. No choice among references by evaluation outcome.',
    'hyperparameters':'Keep original composite config, FLAME lambda .01, WeiDetect K=12/fixed auxiliary set, and frozen individual-envelope model/policy. No threshold or candidate search.',
    'metrics':'Validation ASR trajectories at every round and operational client selections; frozen model evaluations on the existing isolated test split at rounds 10 and 15. No model selection from test outcomes.',
    'qualification':'The test split has been used by earlier studies; it is not a pristine new external test. Calibration/data access differs across methods and is explicit. All outputs remain conditional on the same source updates.',
    'new_training_calls':0,'ToN_IoT_included':False,'fresh_TPM_attestation':False}
save(LAB/'secondary-protocol-before-comparison.json',protocol)
print('SECONDARY FIXED-REFERENCE COMPARISON FROZEN')
