from types import SimpleNamespace as NS

import numpy as np
import pytest
import yaml

from test_live_bounded_aggregation import bounded
from test_live_envelope import put
from fl_forensics.live_bounded_aggregation import backend,materialize,reference,label
from fl_forensics.robust_bounded_aggregation import aggregate_robust_bounded
from fl_forensics.storage import load_json


@pytest.fixture
def robust(bounded):
    path=bounded.public/'in-round-admission.yaml'
    cfg=yaml.safe_load(path.read_text())
    cfg['runtime_admission']['observable_policy']['profile']='live-client-envelope-robust-bounded-v1'
    path.write_text(yaml.safe_dump(cfg))
    return bounded


def test_new_backend_is_bound_and_named(robust):
    operation=backend(robust.workspace,None)
    result=operation([([np.array([2.])],1.),([np.array([.01])],2.),([np.array([.02])],3.)])
    expected,_=aggregate_robust_bounded([[0.]],{'a':[[2.]],'b':[[.01]],'c':[[.02]]},
        masses={'a':1,'b':2,'c':3},mandatory_gates={'a':True,'b':True,'c':True},
        limits=[.1],reference_digest='a'*64,minimum_contributors=1)
    assert all(np.array_equal(a,b) for a,b in zip(result,expected,strict=True))
    assert label(robust.workspace,None)=='RobustBoundedDelta-GeometricMedian-observable-envelope'
    assert 'geometric-median' in operation.forensic_profile['transformation']


def test_new_profile_cannot_claim_audit_only_transformation(robust):
    path=robust.public/'in-round-admission.yaml';cfg=yaml.safe_load(path.read_text())
    cfg['runtime_admission']['observable_policy']['mode']='audit_only'
    path.write_text(yaml.safe_dump(cfg))
    with pytest.raises(ValueError,match='enforced'):reference(robust.workspace)


def test_live_robust_report_binds_final_coefficients_and_rejects_mutation(robust):
    put(robust.public/'in-round-admission-contract.json',{'core':{'minimum_contributors':2}})
    decisions=[]
    for record in robust.records:
        record['bundle'].core.update_sha256='c'*64
        decisions.append((NS(core=NS(client_id=record['client_id'],effective_weight_decimal='1',
                                   num_examples=1,m5_checks=[NS(passed=True)])),None))
    materialize(robust.workspace,robust.records,decisions,True)
    materialize(robust.workspace,robust.records,decisions,False)
    p=robust.workspace/'bounded-update-derivation.json';p.chmod(0o644)
    report=load_json(p)
    assert report['profile']=='live-client-envelope-robust-bounded-v1'
    client=next(iter(report['bounded']['final_coefficients']))
    report['bounded']['final_coefficients'][client]='1'
    put(p,report)
    with pytest.raises(ValueError,match='replay mismatch'):
        materialize(robust.workspace,robust.records,decisions,False)
