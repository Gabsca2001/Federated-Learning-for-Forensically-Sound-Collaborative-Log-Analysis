from pathlib import Path
import sys,unittest,copy
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from retrospective_anomaly_groups import fit_reference,calibrate,detect
from endpoint_recovery_protocol import forged_delta,whole_norm
from fl_forensics.byzantine import update_indicators

def campaign(seed):
    rng=np.random.default_rng(seed);clients=[f'c{i:02d}' for i in range(15)];frames=[]
    for number in range(1,11):
        ds=[[rng.normal(size=3),rng.normal(size=4),rng.normal(size=2)] for _ in clients]
        indicators=update_indicators(ds,client_ids=clients)
        for i in indicators:
            i['relative_norm']=1.+float(rng.uniform(-.01,.01));i['validation_impact']=float(rng.uniform(-.0001,.0001))
        frames.append(dict(round_number=number,client_ids=clients,deltas=ds,indicators=indicators))
    return frames

class AnomalyTests(unittest.TestCase):
    def setUp(self):
        self.ref=fit_reference([campaign(1),campaign(2)])
        self.cal=calibrate([campaign(3),campaign(4),campaign(5)],self.ref)

    def poison(self,frames,clients,numbers):
        for r in frames:
            if r['round_number'] in numbers:
                for i in r['indicators']:
                    if i['client_id'] in clients:i['relative_norm']=1e8

    def test_persistent_three_clients_form_qualified_group(self):
        f=campaign(20);self.poison(f,['c01','c07','c12'],range(1,11))
        v=detect(f,self.ref,self.cal)
        self.assertEqual(v['selected_group'],['c01','c07','c12'])
        self.assertFalse(v['intentional_collusion_proved']);self.assertFalse(v['automatic_exclusion_authorized'])

    def test_transient_spike_is_not_persistent_membership(self):
        f=campaign(21);self.poison(f,['c01','c07','c12'],[1,2])
        v=detect(f,self.ref,self.cal)
        self.assertTrue(set(v['individual_anomalies']).isdisjoint(['c01','c07','c12']))

    def test_disjoint_anomaly_periods_do_not_create_coactive_pair(self):
        f=campaign(22);self.poison(f,['c01'],range(1,6));self.poison(f,['c07'],range(6,11))
        v=detect(f,self.ref,self.cal)
        pair=next(p for p in v['pair_coactivity'] if p['clients']==['c01','c07'])
        self.assertEqual(pair['coactive_fraction'],0.);self.assertFalse(pair['candidate'])

    def test_single_anomaly_does_not_become_colluding_group(self):
        f=campaign(23);self.poison(f,['c01'],range(1,11));v=detect(f,self.ref,self.cal)
        self.assertIn('c01',v['individual_anomalies'])
        self.assertTrue(all(len(g)>=2 for g in v['candidate_groups']))

    def test_overlap_and_changed_reference_are_rejected(self):
        with self.assertRaises(ValueError):calibrate([campaign(1),campaign(3),campaign(4)],self.ref)
        with self.assertRaises(ValueError):detect(campaign(3),self.ref,self.cal)
        wrong=copy.deepcopy(self.ref);wrong['channels']['log_relative_norm']['center']+=1
        with self.assertRaises(ValueError):detect(campaign(20),wrong,self.cal)

    def test_changed_window_and_invalid_values_fail(self):
        f=campaign(25)
        with self.assertRaises(ValueError):detect(f[:9],self.ref,self.cal)
        f[0]['indicators'][0]['relative_norm']=float('nan')
        with self.assertRaises(ValueError):detect(f,self.ref,self.cal)

    def test_relative_radius_uses_whole_vector_and_retains_honest_zero_query(self):
        clean=[np.array([3.]),np.array([4.])];poison=[np.array([-100.]),np.array([1000.])]
        for a in (0.,.125,.5,1.,2.,4.):
            delta,proof=forged_delta(clean,poison,a,'relative-radius')
            self.assertLessEqual(whole_norm(delta),(1+a)*5*(1+1e-12))
            self.assertAlmostEqual(proof['perturbation_norm'],a*5)
        d,_=forged_delta(clean,poison,0.,'relative-radius')
        for a,b in zip(d,clean,strict=True):np.testing.assert_array_equal(a,b)

    def test_malformed_attack_inputs_are_rejected(self):
        for args in [([np.ones(2)],[np.ones(3)],1.,'relative-radius'),
                     ([np.ones(2)],[np.array([np.inf,0])],1.,'unrestricted')]:
            with self.assertRaises(ValueError):forged_delta(*args)

if __name__=='__main__':unittest.main()
