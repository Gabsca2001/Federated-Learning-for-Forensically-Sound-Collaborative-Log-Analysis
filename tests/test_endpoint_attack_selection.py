from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from endpoint_attack_selection import FACTORS,select_endpoint_query
def metric(a,f):return {'clean':{'macro_f1_all_model_classes':f},'complete_trigger':{'asr':a},'component_triggers':{'a':{'asr':a}}}
def qs():return [{'alpha':a,'defined':True,'metrics':metric(0.,.95)} for a in FACTORS]
class EndpointTests(unittest.TestCase):
    def test_damage_and_undefined_candidates_are_not_ranked(self):
        q=qs();q[-1]['metrics']=metric(1.,.5);q[-2]['defined']=False;q[-2]['metrics']=None;q[-3]['metrics']=metric(.9,.94)
        self.assertEqual(select_endpoint_query(q,.95)[0],1.)
    def test_fixed_budget_and_tie_rule(self):
        self.assertEqual(select_endpoint_query(qs(),.95)[0],4.)
        with self.assertRaises(ValueError):select_endpoint_query(qs()[:-1],.95)
    def test_fallback_is_recorded(self):
        q=qs()
        for r in q:r['defined']=False;r['metrics']=None
        a,d=select_endpoint_query(q,.95);self.assertEqual(a,0.);self.assertFalse(d['guard_feasible'])
if __name__=='__main__':unittest.main()
