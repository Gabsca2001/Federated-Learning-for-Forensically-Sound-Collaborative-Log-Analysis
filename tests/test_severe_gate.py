"""Structural response, numerical stability and mandatory-veto tests."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import severe_gate_calibration as severe
from fl_forensics.composite_admission import decide_admission_policies
from fl_forensics.composite_admission_models import TrustSignal


def model(mad=1.):
    refs={n:dict(name=n,direction=severe.DIRECTIONS[n],median=0.,mad=mad,sample_count=100) for n in severe.NAMES}
    return dict(profile='noncompensatory-log-tail-gate-v1',settings={'conditioned':True},references={'iid/0/middle':refs},
                reference_resolution={'iid/0/middle':'iid/0/middle'},relative_scale_floor=1e-9,
                component_limits={'iid':{n:1. for n in severe.NAMES}})


class SevereGateProperties(unittest.TestCase):
    def decide(self,signal,admissible=True):
        trust=TrustSignal(raw_status='passed' if admissible else 'failed',admissible=admissible,
                          risk=0 if admissible else 1,evaluated_checks=[],failed_checks=[],reasons=[])
        return next(d for d in decide_admission_policies(trust=trust,statistics=signal,
            statistical_threshold=severe.bounded(2),composite_threshold=severe.bounded(2)/2,
            composite_downweight_threshold=severe.bounded(1)/2,trust_weight=.5) if d.policy=='gated_composite')

    def test_single_severe_indicator_cannot_be_cancelled_by_normal_others(self):
        for name in severe.NAMES:
            row={n:0. for n in severe.NAMES};row[name]=-100. if severe.DIRECTIONS[name]=='lower' else 100.
            signal,_=severe.score(model(),'iid',1,100,100,row,'candidate')
            self.assertEqual(self.decide(signal).status,'statistically_quarantined')
            self.assertEqual(len(signal.components),0)

    def test_severity_is_monotone_without_original_z_cap(self):
        risks=[]
        for value in (0.,.1,1.,10.,1e6,1e300):
            row={n:0. for n in severe.NAMES};row['relative_norm']=value
            signal,_=severe.score(model(),'iid',1,100,100,row,'candidate');risks.append(signal.risk)
        self.assertEqual(risks,sorted(risks));self.assertTrue(all(0<=r<1 for r in risks))
        self.assertGreater(risks[-1],risks[-2])

    def test_zero_mad_has_numerical_floor_without_jump_to_maximum(self):
        row={n:0. for n in severe.NAMES};row['mad_score']=1e-12
        signal,_=severe.score(model(0.),'iid',1,100,100,row,'candidate')
        self.assertLess(signal.risk,.01)

    def test_trust_veto_holds_for_normal_and_extreme_statistics(self):
        for value in (0.,1e100):
            row={n:0. for n in severe.NAMES};row['relative_norm']=value
            signal,_=severe.score(model(),'iid',1,100,100,row,'candidate')
            self.assertEqual(self.decide(signal,False).status,'trust_quarantined')

    def test_raw_component_details_explain_the_recorded_maximum(self):
        row={n:0. for n in severe.NAMES};row['relative_norm']=20.
        detail=severe.diagnostics(model(),'iid',1,100,100,row)
        self.assertEqual(detail['maximum_severity'],max(v['normalized_severity'] for v in detail['components'].values()))
        self.assertEqual(detail['active_indicators'],['relative_norm'])

    def test_unsupported_reference_fails_instead_of_silent_acceptance(self):
        with self.assertRaises(ValueError):severe.score(model(),'non-iid',1,100,100,{n:0. for n in severe.NAMES},'c')
        with self.assertRaises(ValueError):severe.score(model(),'iid',16,100,100,{n:0. for n in severe.NAMES},'c')


if __name__=='__main__':unittest.main()
