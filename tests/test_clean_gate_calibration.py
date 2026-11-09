"""Meaningful bounds, leakage and support checks for clean-only fitting."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import clean_gate_calibration as cal


class CleanGateCalibrationTests(unittest.TestCase):
    def test_weighted_tail_protects_large_honest_contribution(self):
        self.assertEqual(cal.empirical_quantile([.1,.2,.9],[1,1,98],'0.90'),.9)
        self.assertEqual(cal.empirical_quantile([.1,.2,.9],[1,1,1],'0.50'),.2)

    def test_empirical_count_and_mass_tails_obey_calibration_budget(self):
        scores=[i/101 for i in range(100)];weights=[i+1 for i in range(100)]
        cut=max(cal.empirical_quantile(scores,weights,'0.975'),cal.empirical_quantile(scores,[1]*100,'0.975'))
        self.assertLessEqual(sum(s>cut for s in scores)/100,.025)
        self.assertLessEqual(sum(w for s,w in zip(scores,weights) if s>cut)/sum(weights),.025)

    def test_ties_do_not_create_artificial_rejections(self):
        self.assertEqual(cal.empirical_quantile([1.]*100,[1]*100,'0.975'),1.)

    def test_profile_boundaries_and_unsupported_round(self):
        self.assertEqual(cal.size_bucket(50,100),'middle')
        self.assertEqual(cal.size_bucket(150,100),'middle')
        self.assertEqual(cal.size_bucket(151,100),'large')
        self.assertEqual([cal.stage(n) for n in (1,5,6,10,11,15)],[0,0,1,1,2,2])
        with self.assertRaises(ValueError):cal.stage(16)

    def test_attack_or_test_fields_are_rejected_by_fitter(self):
        record=dict(cohort='iid',round=1,examples=100,cohort_median=100,indicators={n:0. for n in cal.NAMES})
        self.assertEqual(cal.clean_record(record),record)
        for field in ('attacker_id','poisoned','test_accuracy','trigger_asr'):
            with self.assertRaises(ValueError):cal.clean_record({**record,field:True})

    def test_unknown_cohort_has_no_silent_fallback(self):
        with self.assertRaises(ValueError):cal.group_key('unknown',1,100,100,True)

    def test_budget_uses_example_mass_not_only_client_count(self):
        row=dict(statuses={'a':'accepted','b':'statistically_quarantined'},masses={'a':'1','b':'0'},example_counts={'a':1,'b':99})
        result=cal.budget_summary([row])
        self.assertEqual(result['quarantine_rate'],.5)
        self.assertEqual(result['nominal_mass_retention'],.01)


if __name__=='__main__':unittest.main()
