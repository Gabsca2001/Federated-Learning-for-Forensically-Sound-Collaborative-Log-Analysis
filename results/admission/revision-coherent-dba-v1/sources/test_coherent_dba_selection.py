from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from coherent_dba_selection import *
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,poison_local_rows

def metric(asr,f1):return {'clean':{'macro_f1_all_model_classes':f1},'complete_trigger':{'asr':asr},'component_triggers':{'a':{'asr':asr}}}
def queries():return [{'alpha':a,'defined':True,'metrics':metric(0.,.95)} for a in ALPHAS]

class SelectionTests(unittest.TestCase):
    def test_high_asr_with_large_clean_damage_is_not_feasible(self):
        q=queries();q[-1]['metrics']=metric(1.,.5);q[-2]['metrics']=metric(.8,.93)
        alpha,d=select_query(q,.95);self.assertEqual(alpha,64.);self.assertTrue(d['guard_feasible'])
    def test_undefined_quorum_candidate_is_not_a_zero_asr_candidate(self):
        q=queries();q[-1]={'alpha':256.,'defined':False,'metrics':None}
        self.assertEqual(select_query(q,.95)[0],64.)
    def test_no_feasible_query_records_explicit_unmodified_fallback(self):
        q=queries()
        for x in q:x['metrics']=metric(.5,.5)
        alpha,d=select_query(q,.95);self.assertEqual(alpha,0.);self.assertFalse(d['guard_feasible'])
    def test_ties_use_largest_fixed_factor_and_budget_is_checked(self):
        self.assertEqual(select_query(queries(),.95)[0],256.)
        with self.assertRaises(ValueError):select_query(queries()[:-1],.95)
    def test_distributed_and_full_trigger_share_row_budget(self):
        rows=[{'window_id':f'w{i}','features':[0.]*25,'label':'malicious'} for i in range(20)]
        p=DistributedBackdoorPlan(target_label='benign',client_components={'a':[13],'b':[17],'c':[24]},
            trigger_values_decimal={'13':'12','17':'12','24':'12'},poisoned_fraction_decimal='.50',attack_rounds=[1],seed=71107)
        d,dr=poison_local_rows(rows=rows,plan=p,client_id='a',round_number=1,distributed=True)
        f,fr=poison_local_rows(rows=rows,plan=p,client_id='a',round_number=1,distributed=False)
        self.assertEqual(dr['poisoned_window_ids'],fr['poisoned_window_ids'])
        self.assertEqual(dr['modified_feature_values']*3,fr['modified_feature_values'])
        c=poison_commitment(dr);self.assertNotIn('poisoned_window_ids',c);self.assertEqual(c['poisoned_row_count'],10)
        self.assertEqual(c['poisoned_ids_sha256'],poison_commitment(fr)['poisoned_ids_sha256'])

if __name__=='__main__':unittest.main()
