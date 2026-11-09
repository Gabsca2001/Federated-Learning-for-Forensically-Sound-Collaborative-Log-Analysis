"""Support, exact cap, mass separation and actual transformed output checks."""
import copy
from fractions import Fraction
from itertools import combinations
from pathlib import Path
import random,sys,unittest
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from capped_final_aggregation import project_coefficients,aggregate_capped_final,verify_capped_final


def inputs(counts=None):
    counts=counts or [100]*15;clients=[f'c{i:02d}' for i in range(len(counts))]
    return dict(base=[np.zeros(2)],updates={c:[np.array([i/20,(-1)**i/10])] for i,c in enumerate(clients)},
        nominal_counts=dict(zip(clients,counts)),masses=dict(zip(clients,counts)),
        mandatory_gates=dict.fromkeys(clients,True),limits=[.25],reference_digest='a'*64,proposal='sample')


class CappedFinalTests(unittest.TestCase):
    def test_projection_satisfies_every_three_client_subset(self):
        rng=random.Random(1106)
        for _ in range(50):
            p={str(i):rng.randint(1,10000) for i in range(15)}
            beta,report=project_coefficients(p,cap=Fraction(1,9))
            self.assertEqual(sum(beta.values()),1)
            for group in combinations(beta,3):self.assertLessEqual(sum(beta[i] for i in group),Fraction(1,3))
            self.assertEqual(report['final_coefficients'],{i:str(beta[i]) for i in sorted(beta)})

    def test_zeros_are_never_resurrected(self):
        beta,_=project_coefficients({str(i):0 if i<3 else i for i in range(15)},cap='1/9')
        self.assertTrue(all(beta[str(i)]==0 for i in range(3)))

    def test_feasible_boundary_and_infeasible_support(self):
        beta,_=project_coefficients({str(i):i+1 for i in range(9)},cap='1/9')
        self.assertEqual(set(beta.values()),{Fraction(1,9)})
        with self.assertRaisesRegex(ValueError,'support'):project_coefficients({str(i):1 for i in range(8)},cap='1/9')

    def test_ratios_preserved_among_unsaturated_clients(self):
        weights={str(i):10000 if i==0 else i+1 for i in range(15)}
        beta,_=project_coefficients(weights,cap='1/9')
        for a,b in combinations(weights,2):
            if beta[a]<Fraction(1,9) and beta[b]<Fraction(1,9):self.assertEqual(beta[a]/beta[b],Fraction(weights[a],weights[b]))

    def test_original_non_iid_conflict_resolved_by_explicit_beta(self):
        args=inputs([2278,922,714,616,547,385,272,270,250,233,214,141,136,81,37])
        parameters,report=aggregate_capped_final(**args)
        self.assertIsNotNone(parameters);self.assertEqual(report['admission']['retained_nominal_mass'],'1')
        alpha={i:Fraction(v) for i,v in report['admission']['alpha'].items()};beta={i:Fraction(v) for i,v in report['beta'].items()}
        self.assertGreater(sum(sorted(alpha.values(),reverse=True)[:3]),Fraction(7,15))
        self.assertLessEqual(sum(sorted(beta.values(),reverse=True)[:3]),Fraction(1,3))
        self.assertNotEqual(alpha,beta)

    def test_actual_output_is_beta_weighted_clipped_deltas(self):
        args=inputs([400]+[50]*14);parameters,report=aggregate_capped_final(**args)
        expected=np.zeros(2)
        for c,local in args['updates'].items():
            delta=local[0];clipped=delta*min(1,.25/np.linalg.norm(delta))
            expected+=float(Fraction(report['beta'][c]))*clipped
        np.testing.assert_array_equal(parameters[0],expected)
        np.testing.assert_array_equal(verify_capped_final(report=report,**args)[0],parameters[0])

    def test_quarantine_zero_and_mandatory_veto_survive_projection(self):
        args=inputs();args['masses']['c00']=0;args['mandatory_gates']['c01']=False
        _,report=aggregate_capped_final(**args)
        self.assertEqual(report['beta']['c00'],'0');self.assertEqual(report['beta']['c01'],'0')
        self.assertEqual(report['admission']['retained_nominal_mass'],'13/15')

    def test_missing_mass_is_not_repaired_by_projection(self):
        args=inputs([800]+[50]*14);args['masses']['c00']=0
        result,report=aggregate_capped_final(**args)
        self.assertIsNone(result);self.assertIsNone(report['beta'])
        self.assertIn('insufficient_admission_mass',report['reasons'])

    def test_robust_proposal_has_same_guarantees_and_reconstructs(self):
        args=inputs();args['proposal']='robust'
        output,report=aggregate_capped_final(**args)
        self.assertIsNotNone(report['robust_proposal'])
        self.assertLessEqual(Fraction(report['maximum_at_most_k_beta_share']),Fraction(1,3))
        np.testing.assert_array_equal(output[0],verify_capped_final(report=report,**args)[0])

    def test_tampered_weights_and_policy_are_rejected(self):
        args=inputs();_,report=aggregate_capped_final(**args);report=copy.deepcopy(report);report['beta']['c00']='1'
        with self.assertRaisesRegex(ValueError,'reconstruct'):verify_capped_final(report=report,**args)

    def test_invalid_ratios_and_counts_fail(self):
        for bad in (0,'-1','2',0.1):
            with self.assertRaises(ValueError):project_coefficients({'a':1},cap=bad)
        args=inputs();args['nominal_counts']['c00']=True
        with self.assertRaisesRegex(ValueError,'counts'):aggregate_capped_final(**args)


if __name__=='__main__':unittest.main()
