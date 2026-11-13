"""Analytic, invariance, veto and explicit-degeneracy tests."""
from pathlib import Path
import sys,unittest
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from fltrust_screen_aggregation import fltrust_delta,norm_matched_delta

class FLTrustTests(unittest.TestCase):
    def test_analytic_normalized_cosine_average(self):
        d,r=fltrust_delta({'a':[np.array([2.,0.])],'b':[np.array([1.,1.])]},[np.array([1.,0.])],{'a':True,'b':True})
        w=1/(1+1/np.sqrt(2))
        np.testing.assert_allclose(d[0],[w+(1-w)/np.sqrt(2),(1-w)/np.sqrt(2)],rtol=0,atol=1e-15)
        self.assertAlmostEqual(sum(r['normalized_scores'].values()),1.)

    def test_positive_scaling_of_local_update_does_not_change_output(self):
        a,_=fltrust_delta({'a':[np.array([1.,2.])]},[np.array([1.,1.])],{'a':True})
        b,_=fltrust_delta({'a':[np.array([100.,200.])]},[np.array([1.,1.])],{'a':True})
        np.testing.assert_allclose(a,b,rtol=0,atol=1e-15)

    def test_negative_zero_and_vetoed_updates_cannot_contribute(self):
        updates={c:[np.array(v)] for c,v in {'a':[1.,0.],'opposite':[-1.,0.],'orthogonal':[0.,1.],'zero':[0.,0.],'veto':[10.,0.]}.items()}
        d,r=fltrust_delta(updates,[np.array([2.,0.])],{c:c!='veto' for c in updates})
        np.testing.assert_array_equal(d[0],[2.,0.]);self.assertEqual(r['positive_contributors'],1)
        for c in ('opposite','orthogonal','zero','veto'):self.assertEqual(r['effective_raw_delta_coefficients'][c],0.)

    def test_global_vector_normalization_is_not_per_tensor_normalization(self):
        d,r=fltrust_delta({'a':[np.array([3.]),np.array([4.])]},[np.array([0.]),np.array([10.])],{'a':True})
        np.testing.assert_allclose([x[0] for x in d],[6.,8.],rtol=0,atol=1e-14)
        self.assertAlmostEqual(r['aggregate_norm'],10.)

    def test_no_positive_scores_is_explicitly_undefined(self):
        with self.assertRaisesRegex(ValueError,'no positive'):fltrust_delta({'a':[np.array([-1.])]},[np.array([1.])],{'a':True})
        with self.assertRaisesRegex(ValueError,'root'):fltrust_delta({'a':[np.array([1.])]},[np.array([0.])],{'a':True})

    def test_nonfinite_schema_and_roster_errors(self):
        for values in ([np.array([np.nan])],[np.zeros(2)]):
            with self.assertRaises(ValueError):fltrust_delta({'a':values},[np.ones(1)],{'a':True})
        with self.assertRaises(ValueError):fltrust_delta({'a':[np.ones(1)]},[np.ones(1)],{})

    def test_effective_raw_coefficients_are_not_convex_weights(self):
        d,r=fltrust_delta({'a':[np.array([.1])]},[np.array([1.])],{'a':True})
        self.assertEqual(r['normalized_scores']['a'],1.);self.assertEqual(r['effective_raw_delta_coefficients']['a'],10.)
        np.testing.assert_array_equal(d[0],[1.])

    def test_norm_matched_control_and_zero_direction(self):
        d,s=norm_matched_delta([np.array([3.,4.])],2.)
        np.testing.assert_allclose(d[0],[1.2,1.6]);self.assertEqual(s,.4)
        with self.assertRaises(ValueError):norm_matched_delta([np.zeros(2)],1.)
        d,s=norm_matched_delta([np.zeros(2)],0.);self.assertEqual(s,0.)

if __name__=='__main__':unittest.main()
