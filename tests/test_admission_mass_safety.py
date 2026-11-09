"""Authorization, non-readmission, exact boundaries and group-bound checks."""
import copy
from fractions import Fraction
from itertools import combinations
from pathlib import Path
import random
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from admission_mass_safety import MassSafetyPolicy,assess_mass_safety,verify_mass_safety,guarded_aggregation


def population(counts=None):
    counts=counts or [100]*15
    values={f'c{i:02d}':n for i,n in enumerate(counts)}
    return dict(nominal_counts=values,effective_masses=dict(values),
        mandatory_gates={c:True for c in values},statuses={c:'accepted' for c in values},policy=MassSafetyPolicy())


class MassSafetyTests(unittest.TestCase):
    def test_uniform_authorization_preserves_actual_weights(self):
        inputs=population();seen=[]
        output,report=guarded_aggregation(lambda weights:seen.append(weights) or 'checkpoint',**inputs)
        self.assertEqual(output,'checkpoint');self.assertTrue(verify_mass_safety(report,**inputs))
        self.assertEqual(set(seen[0].values()),{Fraction(1,15)})
        self.assertEqual(report['maximum_at_most_k_share'],'1/5')

    def test_count_quorum_does_not_replace_mass_retention(self):
        inputs=population([800]+[50]*14);inputs['statuses']['c00']='statistically_quarantined';inputs['effective_masses']['c00']=0
        called=[];output,report=guarded_aggregation(lambda weights:called.append(weights),**inputs)
        self.assertEqual(report['contributing_clients'],14)
        self.assertIn('insufficient_retained_mass',report['reasons']);self.assertIsNone(output);self.assertEqual(called,[])
        self.assertIsNone(report['authorized_coefficients']);self.assertEqual(report['proposed_coefficients']['c00'],'0')

    def test_concentration_defers_even_without_rejected_mass(self):
        inputs=population([400,300,100]+[10]*12);report=assess_mass_safety(**inputs)
        self.assertEqual(report['retained_mass_fraction'],'1')
        self.assertEqual(report['reasons'],['excessive_group_share'])

    def test_mass_floor_equality_is_authorized_without_readmission(self):
        inputs=population()
        for c in ('c00','c01','c02'):inputs['statuses'][c]='statistically_quarantined';inputs['effective_masses'][c]=0
        report=assess_mass_safety(**inputs);self.assertTrue(report['aggregation_authorized'])
        self.assertEqual(report['retained_mass_fraction'],'4/5')
        for c in ('c00','c01','c02'):self.assertEqual(report['authorized_coefficients'][c],'0')

    def test_group_cap_equality_is_authorized(self):
        report=assess_mass_safety(**population([2]*3+[1]*12))
        self.assertTrue(report['aggregation_authorized']);self.assertEqual(report['maximum_at_most_k_share'],'1/3')

    def test_downweight_mass_must_match_action_and_bound_count(self):
        inputs=population();inputs['statuses']['c00']='accepted_downweighted';inputs['effective_masses']['c00']='50'
        self.assertEqual(assess_mass_safety(**inputs)['retained_mass_fraction'],'29/30')
        inputs['effective_masses']['c00']='100'
        with self.assertRaisesRegex(ValueError,'mass/action/count'):assess_mass_safety(**inputs)

    def test_trust_veto_cannot_be_bypassed(self):
        inputs=population();inputs['mandatory_gates']['c00']=False
        with self.assertRaisesRegex(ValueError,'veto'):assess_mass_safety(**inputs)
        inputs['statuses']['c00']='trust_quarantined';inputs['effective_masses']['c00']=0
        report=assess_mass_safety(**inputs);self.assertEqual(report['authorized_coefficients']['c00'],'0')

    def test_all_quarantined_has_undefined_coefficients(self):
        inputs=population()
        for c in inputs['statuses']:inputs['statuses'][c]='statistically_quarantined';inputs['effective_masses'][c]=0
        report=assess_mass_safety(**inputs)
        self.assertIsNone(report['proposed_coefficients']);self.assertIsNone(report['authorized_coefficients'])
        self.assertIn('zero_effective_mass',report['reasons'])

    def test_roster_substitution_and_float_masses_fail_before_backend(self):
        inputs=population();inputs['effective_masses'].pop('c00')
        with self.assertRaisesRegex(ValueError,'roster'):assess_mass_safety(**inputs)
        inputs=population();inputs['effective_masses']['c00']=100.0
        with self.assertRaisesRegex(ValueError,'exact'):assess_mass_safety(**inputs)

    def test_modified_assessment_or_policy_does_not_verify(self):
        inputs=population();report=assess_mass_safety(**inputs);changed=copy.deepcopy(report)
        changed['authorized_coefficients']['c00']='1'
        with self.assertRaisesRegex(ValueError,'reconstruct'):verify_mass_safety(changed,**inputs)
        inputs['policy']=MassSafetyPolicy(maximum_group_share=Fraction(1,2))
        with self.assertRaisesRegex(ValueError,'reconstruct'):verify_mass_safety(report,**inputs)

    def test_maximum_subset_is_exact_for_every_small_subset(self):
        rng=random.Random(1729)
        for _ in range(50):
            inputs=population([rng.randint(1,100) for _ in range(6)])
            inputs['policy']=MassSafetyPolicy(minimum_contributors=2,maximum_group_size=2,maximum_group_share=Fraction(4,5))
            report=assess_mass_safety(**inputs);weights=report['proposed_coefficients']
            observed=max(sum((Fraction(weights[c]) for c in subset),Fraction(0)) for n in (1,2) for subset in combinations(weights,n))
            self.assertEqual(Fraction(report['maximum_at_most_k_share']),observed)

    def test_invalid_policy_and_counts_fail_explicitly(self):
        for kwargs in ({'minimum_contributors':True},{'maximum_group_size':0},{'maximum_group_share':'0'},
                       {'minimum_retained_mass':'3/2'},{'downweight_factor':0.5}):
            with self.assertRaises(ValueError):MassSafetyPolicy(**kwargs)
        inputs=population();inputs['nominal_counts']['c00']=True
        with self.assertRaisesRegex(ValueError,'integers'):assess_mass_safety(**inputs)


if __name__=='__main__':unittest.main()
