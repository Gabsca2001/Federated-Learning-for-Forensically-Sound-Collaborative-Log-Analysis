"""Analytical operator checks and meaningful protocol failure cases."""
from pathlib import Path
import sys, unittest, copy
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from normonly_aggregation import normonly_delta
import normonly_gradient_protocol as p
from fltrust_screen_aggregation import fltrust_delta

class NormOnlyTests(unittest.TestCase):
    def test_orthogonal_and_opposing_vectors_remain_equal_weight(self):
        d={'a':[np.array([2.,0.])], 'b':[np.array([-20.,0.])], 'c':[np.array([0.,7.])]}
        result, event=normonly_delta(d,[np.array([3.,0.])],dict.fromkeys(d, True))
        np.testing.assert_allclose(result[0],[0.,1.],atol=1e-15)
        self.assertEqual(event['normalized_scores'],dict.fromkeys(d,1/3))
        _, filtered=fltrust_delta(d,[np.array([3.,0.])],dict.fromkeys(d,True))
        self.assertEqual(filtered['positive_contributors'],1)

    def test_reference_rotation_and_local_positive_scaling_do_not_change_output(self):
        d={'a':[np.array([3.,4.])], 'b':[np.array([-8.,6.])]}
        a,_=normonly_delta(d,[np.array([2.,0.])],dict.fromkeys(d,True))
        scaled={c:[v[0]*100] for c,v in d.items()}
        b,_=normonly_delta(scaled,[np.array([0.,-2.])],dict.fromkeys(d,True))
        np.testing.assert_allclose(a,b,atol=1e-15)

    def test_mandatory_veto_and_zero_vector_cannot_gain_weight(self):
        d={'a':[np.array([1.,0.])], 'b':[np.array([1e6,0.])], 'c':[np.zeros(2)]}
        out,event=normonly_delta(d,[np.array([2.,0.])],{'a':True,'b':False,'c':True})
        np.testing.assert_array_equal(out[0],[2.,0.])
        self.assertEqual(event['scores'],{'a':1.,'b':0.,'c':0.})

    def test_whole_vector_normalization_not_per_tensor(self):
        out,event=normonly_delta({'a':[np.array([3.]),np.array([4.])]},[np.array([0.]),np.array([10.])],{'a':True})
        np.testing.assert_allclose(np.concatenate(out),[6.,8.])
        self.assertEqual(event['aggregate_norm'],10.)

    def test_undefined_inputs_fail(self):
        for d,root,gates in [({'a':[np.ones(2)]},[np.zeros(2)],{'a':True}),
            ({'a':[np.zeros(2)]},[np.ones(2)],{'a':True}),
            ({'a':[np.ones(3)]},[np.ones(2)],{'a':True}),
            ({'a':[np.array([np.nan,1.])]},[np.ones(2)],{'a':True})]:
            with self.assertRaises(ValueError):normonly_delta(d,root,gates)

    def fixture(self, count=15):
        clients=[f'c{i:02d}' for i in range(15)];base=[np.zeros(2)]
        ctx=p.make_context(parent_model_sha256='a'*64,base_tensor_digest=p.digest(p.array_record(base)),round_number=1,
            attempt_id='ablation',protocol_sha256='b'*64,loss_contract_sha256='c'*64,roster=clients,
            method='coherent_normonly',root_reference_sha256='d'*64)
        updates={c:p.update_record(c,ctx,[np.array([-1.,0.])],1) for c in clients[:count]}
        root={'context_digest':ctx['context_digest'],'reference_sha256':'d'*64,'delta':[np.array([1.,0.])],'delta_digest':p.delta_digest([np.array([1.,0.])])}
        return base,updates,root,ctx

    def test_opposing_quorum_commits_and_reconstructs(self):
        base,u,r,c=self.fixture();params,event=p.assess_round(base,u,r,c)
        np.testing.assert_allclose(params[0],[-1.,0.]);self.assertEqual(event['positive_contributors'],15)
        p.verify_round(base,u,r,c,event)
        altered=copy.deepcopy(event);altered['aggregation']['scores']['c00']=0.
        with self.assertRaises(ValueError):p.verify_round(base,u,r,c,altered)

    def test_insufficient_quorum_preserves_parent_without_endpoint(self):
        base,u,r,c=self.fixture(9);params,event=p.assess_round(base,u,r,c)
        self.assertIsNone(params);state=p.transition(p.initial_state('a'*64,'b'*64),event,None)
        self.assertEqual(state['phase'],'paused');self.assertEqual(state['parent_model_sha256'],'a'*64)
        self.assertEqual(state['last_committed_round'],0)

    def test_stale_context_rejected(self):
        base,u,r,c=self.fixture();u['c00']['context_digest']='e'*64
        with self.assertRaises(ValueError):p.assess_round(base,u,r,c)

if __name__=='__main__':unittest.main()
