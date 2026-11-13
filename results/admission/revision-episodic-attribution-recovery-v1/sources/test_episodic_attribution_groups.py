from pathlib import Path
import sys,unittest,copy
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from episodic_attribution_groups import fit_reference,calibrate,detect
from test_retrospective_anomaly_groups import campaign

class EpisodeTests(unittest.TestCase):
    def setUp(self):
        self.ref=fit_reference([campaign(1),campaign(2)])
        self.cal=calibrate([campaign(3),campaign(4),campaign(5)],self.ref)

    def quiet(self,seed):
        frames=campaign(seed);center=float(np.expm1(self.ref['channels']['log_relative_norm']['center']))
        for r in frames:
            for i in r['indicators']:i['relative_norm']=center;i['validation_impact']=0.
        return frames

    def magnitude(self,frames,clients,rounds):
        for r in frames:
            if r['round_number'] in rounds:
                for i in r['indicators']:
                    if i['client_id'] in clients:i['relative_norm']=1e8

    def test_validation_risk_is_retained_without_becoming_actor_anomaly(self):
        f=self.quiet(20)
        for r in f:
            for i in r['indicators']:
                if i['client_id'] in ['c01','c02','c03']:i['validation_impact']=.5
        result=detect(f,self.ref,self.cal)
        self.assertEqual(result['utility_risk_clients'],['c01','c02','c03'])
        self.assertEqual(result['individual_anomalies'],[]);self.assertEqual(result['selected_group'],[])

    def test_five_separated_excesses_are_detected(self):
        f=self.quiet(21);self.magnitude(f,['c01','c07','c12'],[1,2,4,7,10]);r=detect(f,self.ref,self.cal)
        self.assertEqual(r['selected_group'],['c01','c07','c12'])
        self.assertEqual(r['magnitude_excess_rounds']['c12'],[1,2,4,7,10])
        self.assertFalse(r['intentional_collusion_proved']);self.assertFalse(r['automatic_exclusion_authorized'])

    def test_two_excesses_are_explicitly_below_the_episode_contract(self):
        f=self.quiet(22);self.magnitude(f,['c01','c07','c12'],[2,7]);r=detect(f,self.ref,self.cal)
        self.assertEqual(r['individual_anomalies'],[]);self.assertEqual(r['selected_group'],[])

    def test_unlike_channels_cannot_create_a_group_edge(self):
        f=self.quiet(23);self.magnitude(f,['c01','c07'],range(1,11))
        for frame in f:
            next(i for i in frame['indicators'] if i['client_id']=='c12')['validation_impact']=.5
        result=detect(f,self.ref,self.cal)
        self.assertEqual(result['selected_group'],['c01','c07']);self.assertEqual(result['utility_risk_clients'],['c12'])

    def test_nonoverlapping_episode_clients_are_not_called_coactive(self):
        f=self.quiet(24);self.magnitude(f,['c01'],[1,2,3]);self.magnitude(f,['c07'],[7,8,9]);r=detect(f,self.ref,self.cal)
        self.assertEqual(r['individual_anomalies'],['c01','c07']);self.assertEqual(r['selected_group'],[])

    def test_oversized_clique_is_not_cut_to_expected_attacker_count(self):
        f=self.quiet(25);g=['c00','c01','c02','c03','c04','c05'];self.magnitude(f,g,range(1,11));r=detect(f,self.ref,self.cal)
        self.assertIn(g,r['candidate_groups']);self.assertEqual(r['selected_group'],[])

    def test_overlap_and_modified_episode_contract_fail(self):
        with self.assertRaises(ValueError):calibrate([campaign(1),campaign(4),campaign(5)],self.ref)
        with self.assertRaises(ValueError):detect(campaign(3),self.ref,self.cal)
        c=copy.deepcopy(self.cal);c['minimum_excess_rounds']=2
        with self.assertRaises(ValueError):detect(self.quiet(26),self.ref,c)

    def test_episode_threshold_is_clean_campaign_maximum_for_the_new_statistic(self):
        self.assertEqual(self.cal['episode_score_threshold'],max(self.cal['clean_campaign_episode_maxima']))
        self.assertGreaterEqual(self.cal['coactive_round_count_threshold'],2)
        self.assertFalse(self.cal['labels_used'])

if __name__=='__main__':unittest.main()
