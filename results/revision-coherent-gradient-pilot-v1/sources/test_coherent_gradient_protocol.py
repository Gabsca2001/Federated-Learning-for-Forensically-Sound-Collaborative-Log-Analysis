from pathlib import Path
import sys,unittest,copy
import numpy as np
import torch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from coherent_gradient_protocol import *

def fixture(positive=15,received=15):
    clients=[f'c{i:02d}' for i in range(15)]
    ctx=make_context(parent_model_sha256='a'*64,base_tensor_digest=digest(array_record([np.zeros(2)])),round_number=1,attempt_id='attempt1',protocol_sha256='b'*64,
        loss_contract_sha256='c'*64,roster=clients,method='coherent_fltrust',root_reference_sha256='d'*64)
    updates={c:update_record(c,ctx,[np.array([1. if i<positive else -1.,0.])],10) for i,c in enumerate(clients[:received])}
    root={'context_digest':ctx['context_digest'],'reference_sha256':'d'*64,'delta':[np.array([1.,0.])],'delta_digest':delta_digest([np.array([1.,0.])])}
    return [np.zeros(2)],updates,root,ctx

class CoherentTests(unittest.TestCase):
    def test_supported_round_commits_exactly_one_step(self):
        base,u,r,c=fixture();params,event=assess_round(base,u,r,c)
        np.testing.assert_allclose(params[0],[1.,0.],rtol=0,atol=2e-16)
        state=transition(initial_state('a'*64,'b'*64),event,'e'*64)
        self.assertEqual(state['last_committed_round'],1);self.assertEqual(state['parent_model_sha256'],'e'*64)

    def test_nine_positive_clients_pause_without_a_checkpoint(self):
        base,u,r,c=fixture(9);params,event=assess_round(base,u,r,c)
        self.assertIsNone(params);self.assertEqual(event['positive_contributors'],9)
        state=transition(initial_state('a'*64,'b'*64),event,None)
        self.assertEqual(state['phase'],'paused');self.assertEqual(state['last_committed_round'],0)
        self.assertEqual(state['parent_model_sha256'],'a'*64)

    def test_missing_updates_do_not_count_as_contributors(self):
        base,u,r,c=fixture(received=9);params,event=assess_round(base,u,r,c)
        self.assertIsNone(params);self.assertEqual(len(event['missing_clients']),6)
        self.assertEqual(event['reasons'],['insufficient_eligible_contributors'])

    def test_paused_attempt_cannot_be_retried_as_training_progress(self):
        base,u,r,c=fixture(9);_,event=assess_round(base,u,r,c)
        state=transition(initial_state('a'*64,'b'*64),event,None)
        with self.assertRaises(ValueError):transition(state,event,None)
        with self.assertRaises(ValueError):transition(initial_state('a'*64,'b'*64),event,'e'*64)

    def test_mandatory_veto_survives_positive_alignment(self):
        base,u,r,c=fixture();u['c00']['mandatory_gate']=False
        _,event=assess_round(base,u,r,c)
        self.assertEqual(event['aggregation']['normalized_scores']['c00'],0.)
        self.assertEqual(event['positive_contributors'],14)

    def test_stale_client_and_root_are_rejected(self):
        for target in ('client','root'):
            base,u,r,c=fixture()
            if target=='client':u['c00']['context_digest']='f'*64
            else:r['context_digest']='f'*64
            with self.subTest(target=target),self.assertRaises(ValueError):assess_round(base,u,r,c)

    def test_changed_payload_is_rejected(self):
        base,u,r,c=fixture();u['c00']['delta'][0][0]=2.
        with self.assertRaises(ValueError):assess_round(base,u,r,c)

    def test_zero_reference_and_opposed_updates_pause(self):
        base,u,r,c=fixture(0);params,event=assess_round(base,u,r,c)
        self.assertIsNone(params);self.assertEqual(event['decision'],'defer')
        r['delta']=[np.zeros(2)];r['delta_digest']=delta_digest(r['delta'])
        params,event=assess_round(base,u,r,c);self.assertIsNone(params)

    def test_quorum_cannot_be_lowered_inside_the_context(self):
        base,u,r,c=fixture();c['minimum_positive_contributors']=9
        c['context_digest']=digest({k:v for k,v in c.items() if k!='context_digest'})
        with self.assertRaises(ValueError):assess_round(base,u,r,c)

    def test_wrong_parent_or_round_cannot_advance_state(self):
        base,u,r,c=fixture();_,event=assess_round(base,u,r,c)
        with self.assertRaises(ValueError):transition(initial_state('f'*64,'b'*64),event,'e'*64)
        state=initial_state('a'*64,'b'*64);state['last_committed_round']=1
        with self.assertRaises(ValueError):transition(state,event,'e'*64)

    def test_changed_report_is_rejected(self):
        base,u,r,c=fixture(9);_,event=assess_round(base,u,r,c);event['positive_contributors']=10
        with self.assertRaises(ValueError):verify_round(base,u,r,c,event)
        with self.assertRaises(ValueError):transition(initial_state('a'*64,'b'*64),event,None)

    def test_numerical_base_is_bound_to_context(self):
        base,u,r,c=fixture()
        with self.assertRaises(ValueError):assess_round([np.ones(2)],u,r,c)

    def test_common_loss_has_no_local_weight_sum_normalization(self):
        model=torch.nn.Linear(2,2).double()
        with torch.no_grad():model.weight.zero_();model.bias.zero_()
        g,_=common_loss_gradient(model,torch.eye(2,dtype=torch.float64),torch.tensor([0,1]),torch.tensor([1.,3.],dtype=torch.float64),torch)
        np.testing.assert_array_equal(g[0],[[-.25,.75],[.25,-.75]])
        np.testing.assert_array_equal(g[1],[.5,-.5])

    def test_sample_weighted_client_gradients_equal_the_pooled_common_loss(self):
        def get(x,y):
            model=torch.nn.Linear(2,2).double()
            with torch.no_grad():model.weight.zero_();model.bias.zero_()
            return common_loss_gradient(model,x,y,torch.tensor([1.,3.],dtype=torch.float64),torch)[0]
        x=torch.tensor([[1.,0.],[0.,1.],[1.,1.]],dtype=torch.float64);y=torch.tensor([0,1,1])
        first=get(x[:1],y[:1]);second=get(x[1:],y[1:]);pooled=get(x,y)
        for a,b,c in zip(first,second,pooled,strict=True):np.testing.assert_allclose(a/3+2*b/3,c,rtol=0,atol=1e-15)

if __name__=='__main__':unittest.main()
