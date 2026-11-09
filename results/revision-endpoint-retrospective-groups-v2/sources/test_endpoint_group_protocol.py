"""Numerical renormalization, quorum and outcome-independent control selection."""
from pathlib import Path
import sys, unittest
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import coherent_gradient_protocol as p
from endpoint_group_protocol import removal_plan,remove_and_aggregate


class GroupInterventionTests(unittest.TestCase):
    def fixture(self):
        clients=[f'c{i:02d}' for i in range(15)];base=[np.array([10.])]
        c=p.make_context(parent_model_sha256='a'*64,base_tensor_digest=p.digest(p.array_record(base)),round_number=10,
            attempt_id='late-removal',protocol_sha256='b'*64,loss_contract_sha256='c'*64,roster=clients,method='coherent_fedavg')
        u={name:p.update_record(name,c,[np.array([float(i)])],i+1) for i,name in enumerate(clients)}
        return base,u,c

    def test_sample_weights_renormalize_on_same_fixed_roster(self):
        base,u,c=self.fixture();out,event=remove_and_aggregate(base,u,c,['c14'])
        expected=10+sum(i*(i+1) for i in range(14))/sum(range(1,15))
        np.testing.assert_allclose(out[0],[expected],rtol=0,atol=1e-14)
        self.assertEqual(c['roster'],[f'c{i:02d}' for i in range(15)])
        self.assertEqual(event['missing_clients'],['c14'])
        self.assertEqual(set(event['aggregation']['coefficients']),set(u)-{'c14'})

    def test_removing_six_pauses_without_new_model(self):
        base,u,c=self.fixture();out,event=remove_and_aggregate(base,u,c,sorted(u)[:6])
        self.assertIsNone(out);state=p.transition({'phase':'active','last_committed_round':9,'parent_model_sha256':'a'*64,'protocol_sha256':'b'*64},event,None)
        self.assertEqual(state['parent_model_sha256'],'a'*64);self.assertEqual(state['last_committed_round'],9)

    def test_vetoed_survivor_cannot_be_reenabled_by_removal(self):
        base,u,c=self.fixture();u['c00']['mandatory_gate']=False
        _,e=remove_and_aggregate(base,u,c,['c14'])
        self.assertEqual(e['aggregation']['coefficients']['c00'],0.)

    def test_invalid_or_duplicate_removal_rejected(self):
        base,u,c=self.fixture()
        for group in (['unknown'],['c00','c00']):
            with self.assertRaises(ValueError):remove_and_aggregate(base,u,c,group)

    def test_controls_preserve_size_and_are_best_available_mass_match(self):
        clients=[f'c{i:02d}' for i in range(15)];counts={c:i+1 for i,c in enumerate(clients)}
        sel={'v2':['c00','c01'],'v3':['c00','c01','c02']};truth=['c00','c01','c02']
        a=removal_plan(sel,clients,counts,truth);b=removal_plan(sel,list(reversed(clients)),counts,list(reversed(truth)))
        self.assertEqual(a,b)
        from itertools import combinations
        for comp in a['comparisons']:
            controls=comp['hash_controls']+[comp['mass_matched_control']]
            self.assertTrue(all(len(g)==len(comp['group']) and not set(g)&set(truth) for g in controls))
            residual=abs(comp['group_sample_count']-comp['control_sample_count'])
            self.assertEqual(residual,min(abs(sum(counts[c] for c in g)-comp['group_sample_count'])
                for g in combinations(clients[3:],len(comp['group']))))

    def test_no_detected_group_stays_empty_and_oracle_is_separate(self):
        clients=[f'c{i:02d}' for i in range(15)];counts=dict.fromkeys(clients,1)
        plan=removal_plan({'v2':[],'v3':[]},clients,counts,clients[:3])
        self.assertEqual([c['method'] for c in plan['comparisons']],['oracle-diagnostic'])
        self.assertTrue(all(not any(r.startswith(('v2','v3')) for r in x['roles']) for x in plan['removals']))

if __name__=='__main__':unittest.main()
