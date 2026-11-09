"""Numerical profile and no-band controls for the new independent histories."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
import numpy as np
from fl_forensics.federated_model import dependencies

scripts = Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(scripts))
spec = importlib.util.spec_from_file_location('gate_study',scripts/'revision_gate_trajectories.py')
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)


class GateTrajectoryNumerics(unittest.TestCase):
    def setUp(self):
        self.gen = SimpleNamespace(clients=['a','b','c'],rows={'a':[0]*2,'b':[0]*3,'c':[0]*5},deps=dependencies())
        self.base = dict(parameters=[dict(name='x',dtype='float32',shape=[1],values=[0.])])
        self.local = [[np.array([v],dtype=np.float32)] for v in (1,2,4)]
        self.settings = dict(accepted_downweight_factor=.5,minimum_contributors=2)

    def test_live_full_model_weighting_and_exact_coefficients(self):
        state = dict(decisions={c:{'gated_composite':dict(contributes=True,status='accepted_downweighted' if c=='c' else 'accepted')}
                                 for c in self.gen.clients})
        model,masses,coeff = study.numerical(self.base,self.local,self.gen,state,self.settings,'gated_composite')
        self.assertEqual(masses['c'],study.Fraction(5,2))
        self.assertEqual(coeff,dict(a='4/15',b='2/5',c='1/3'))
        self.assertAlmostEqual(model['parameters'][0]['values'][0],(2+6+10)/7.5,places=6)

    def test_lost_quorum_is_undefined(self):
        state = dict(decisions={c:{'sequential':dict(contributes=c=='a',status='accepted' if c=='a' else 'statistically_quarantined')}
                                 for c in self.gen.clients})
        model,_,coeff = study.numerical(self.base,self.local,self.gen,state,self.settings,'sequential')
        self.assertIsNone(model);self.assertIsNone(coeff)

    def test_no_band_negative_control_matches_sequential_export(self):
        state = dict(decisions={c:{p:dict(contributes=c!='b',status='accepted' if c!='b' else 'statistically_quarantined')
                                  for p in ('sequential','composite_no_band')} for c in self.gen.clients})
        before = study.numerical(self.base,self.local,self.gen,state,self.settings,'sequential')
        after = study.numerical(self.base,self.local,self.gen,state,self.settings,'composite_no_band')
        self.assertEqual(before,after)


if __name__=='__main__':unittest.main()
