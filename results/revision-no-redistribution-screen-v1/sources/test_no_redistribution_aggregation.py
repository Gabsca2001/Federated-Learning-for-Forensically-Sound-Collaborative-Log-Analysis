"""Check coefficient contracts and actual non-renormalized numerical behavior."""
import sys,unittest
from pathlib import Path
from fractions import Fraction as F
from itertools import combinations
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from no_redistribution_aggregation import coefficient_variants,blend_clipped_deltas

class NoRedistributionTests(unittest.TestCase):
    def test_cut_never_increases_any_original_coefficient(self):
        p,b,m,r=coefficient_variants({'large':99,**{str(i):F(1,14) for i in range(14)},'zero':0})
        self.assertTrue(all(b[i]<=p[i] for i in p));self.assertEqual(b['zero'],0)
        self.assertEqual(sum(b.values())+r,1);self.assertEqual(sum(m.values()),sum(b.values()))
        for group in combinations(b,3):self.assertLessEqual(sum(b[i] for i in group),F(1,3))

    def test_checkpoint_inclusive_bound_is_not_client_only_bound(self):
        _,b,_,r=coefficient_variants({'large':99,**{str(i):F(1,14) for i in range(14)}})
        self.assertGreater(r,0)
        self.assertGreater(sum(sorted(b.values(),reverse=True)[:3])/sum(b.values()),F(1,3))

    def test_feasible_proposal_remains_unchanged(self):
        p,b,m,r=coefficient_variants({str(i):1 for i in range(15)})
        self.assertEqual(p,b);self.assertEqual(p,m);self.assertEqual(r,0)

    def test_matched_step_preserves_original_ratios(self):
        p,b,m,r=coefficient_variants({'a':8,'b':1,'c':1})
        self.assertEqual(m['a']/m['b'],p['a']/p['b'])
        self.assertEqual(sum(b.values()),sum(m.values()))

    def test_actual_blend_does_not_normalize_client_coefficients(self):
        base=[np.array([10.])];d={'a':[np.array([2.])],'b':[np.array([-1.])]}
        out=blend_clipped_deltas(base,d,{'a':F(1,9),'b':F(1,10)},{'a':True,'b':True})
        np.testing.assert_allclose(out[0],[10+2/9-1/10],rtol=0,atol=1e-14)
        np.testing.assert_array_equal(base[0],[10.])

    def test_veto_cannot_receive_positive_coefficient(self):
        with self.assertRaisesRegex(ValueError,'veto'):
            blend_clipped_deltas([np.zeros(1)],{'a':[np.ones(1)]},{'a':F(1,9)},{'a':False})
        np.testing.assert_array_equal(blend_clipped_deltas([np.zeros(1)],{'a':[np.ones(1)]},{'a':0},{'a':False})[0],[0.])

    def test_invalid_coefficient_inputs(self):
        for p in ({},{'a':-1},{'a':0},{'a':True},{'a':'nan'}):
            with self.subTest(p=p),self.assertRaises((ValueError,ZeroDivisionError)):coefficient_variants(p)
        for cap in (0,-1,2):
            with self.subTest(cap=cap),self.assertRaises(ValueError):coefficient_variants({'a':1},cap)

    def test_invalid_blend_cannot_pass_silently(self):
        for value in (-1,2):
            with self.subTest(value=value),self.assertRaises(ValueError):
                blend_clipped_deltas([np.zeros(1)],{'a':[np.ones(1)]},{'a':value},{'a':True})
        with self.assertRaises(ValueError):blend_clipped_deltas([np.zeros(2)],{'a':[np.ones(1)]},{'a':F(1,9)},{'a':True})
        with self.assertRaises(ValueError):blend_clipped_deltas([np.zeros(1)],{'a':[np.array([np.nan])]},{'a':0},{'a':True})

if __name__=='__main__':unittest.main()
