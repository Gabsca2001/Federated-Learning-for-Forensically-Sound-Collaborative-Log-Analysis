from pathlib import Path
import sys,unittest
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from selector_diagnostic_math import active_intervals,class_effect,confusion_metrics,decompose

def frames(norm_scores,validation_scores):
    clients=[f'c{i:02d}' for i in range(15)];result=[]
    for t in range(10):
        items=[]
        for i,c in enumerate(clients):
            n=norm_scores[t] if i==0 else 0.;v=validation_scores[t] if i==0 else 0.
            items.append(dict(client_id=c,delta_l2=1.,relative_norm=float(np.expm1(n)),validation_impact=v))
        result.append(dict(round_number=t+1,client_ids=clients,indicators=items))
    return result

REF={'profile':'persistent-anomaly-coactivity-v4','labels_used':False,
    'features':['log_relative_norm','validation_impact'],
    'channels':{'log_relative_norm':{'center':0.,'scale':1.},'validation_impact':{'center':0.,'scale':1.}}}

class DiagnosticTests(unittest.TestCase):
    def test_disjoint_intervals_and_singletons(self):
        self.assertEqual(active_intervals([True,True,False,True,False,True]),[[1,2],[4,4],[6,6]])
        self.assertEqual(active_intervals([False]*10),[])

    def test_median_of_channel_maxima_cannot_be_replaced_by_channel_medians(self):
        f=frames([3.]*5+[0.]*5,[0.]*5+[3.]*5)
        c=decompose(f,REF,{'persistent_score_threshold':2.})['clients'][0]
        self.assertEqual(c['persistent_score'],3.);self.assertEqual(c['median_norm_score'],1.5)
        self.assertEqual(c['median_validation_score'],1.5);self.assertTrue(c['anomalous'])

    def test_five_large_rounds_can_be_missed_without_changing_threshold(self):
        c=decompose(frames([3.]*5+[0.]*5,[0.]*10),REF,{'persistent_score_threshold':2.})['clients'][0]
        self.assertEqual(c['fifth_order_score'],0.);self.assertEqual(c['sixth_order_score'],3.)
        self.assertEqual(c['persistent_score'],1.5);self.assertFalse(c['anomalous'])
        self.assertEqual(c['active_rounds'],[1,2,3,4,5])

    def test_rare_class_macro_f1_jump_can_coexist_with_small_accuracy_change(self):
        d=class_effect([[999,0],[0,1]],[[999,0],[1,0]])
        self.assertAlmostEqual(d['accuracy_change'],-.001)
        self.assertLess(d['macro_f1_change'],-.49)
        self.assertEqual(d['supports'],[999,1])

    def test_changed_population_is_not_a_paired_effect(self):
        with self.assertRaises(ValueError):class_effect([[9,0],[0,1]],[[10,0],[0,1]])
        with self.assertRaises(ValueError):confusion_metrics([[0,0],[0,0]])

if __name__=='__main__':unittest.main()
