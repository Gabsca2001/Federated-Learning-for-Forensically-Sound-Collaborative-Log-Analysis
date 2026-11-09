"""Individual clean risk envelopes with confirmed, non-receding current evidence."""
from __future__ import annotations
import copy
from fractions import Fraction
import numpy as np
from .current_evidence_policy import CurrentEvidencePolicy
from .sequential_decision import digest

PROFILE='client-envelope-retreat-policy-v1'


class ClientEnvelopePolicy:
    def __init__(self,calibration,envelope,*,minimum_contributors=8):
        self._prior=CurrentEvidencePolicy(calibration,minimum_contributors=minimum_contributors)
        self.cal=copy.deepcopy(calibration);self.envelope=copy.deepcopy(envelope)
        self.clients=list(self._prior.clients);self.minimum=minimum_contributors
        if envelope.get('profile')!='clean-client-risk-envelope-v1' or envelope['clients']!=self.clients or envelope['cohort_id']!=calibration['cohort_id']:
            raise ValueError('client envelope schema mismatch')
        self.limits=np.asarray(envelope['tensor_risk_limits'],dtype=float)
        if self.limits.shape!=(len(self.clients),2) or not np.isfinite(self.limits).all() or np.any(self.limits<=0):
            raise ValueError('invalid individual clean envelope')
        if envelope['retained_peak_fraction']!=.5:raise ValueError('changed evidence retreat rule')
        self.envelope_digest=digest(envelope);self.round=0;self.head='0'*64
        self._peak=np.zeros(len(self.clients));self._previous_retained=np.zeros(len(self.clients),dtype=bool)
        self._quarantined=set();self._last_previous=None;self._last_basis_digest=None;self.last_result=None

    def step(self,round_number,risk,*,context_supported,mandatory_gate,masses,expected_previous_digest,source_observation_sha256):
        if type(round_number) is not int or round_number<1:raise ValueError('round must be positive integer')
        retry=round_number==self.round
        if expected_previous_digest!=(self._last_previous if retry else self.head):raise ValueError('trusted predecessor mismatch')
        if not retry and round_number!=self.round+1:raise ValueError('round order mismatch')
        basis=self._prior.step(round_number,risk,context_supported=context_supported,mandatory_gate=mandatory_gate,masses=masses,
            expected_previous_digest=self._prior._last_previous if retry else self._prior.head,
            source_observation_sha256=source_observation_sha256)
        if retry:
            if basis['decision_digest']!=self._last_basis_digest:raise ValueError('conflicting evidence retry')
            return copy.deepcopy(self.last_result)
        if basis['supported']:
            raw=np.stack([np.asarray(risk[v],dtype=float) for v in ('conditioned','state-disabled')],axis=1)
            excess=(raw-self.limits).min(axis=1);high=excess>0
            peak=np.where(high,np.maximum(self._peak,excess),0.)
            retained=high&(excess>=.5*peak);confirmed=retained&self._previous_retained
        else:
            excess=np.zeros(len(self.clients));high=np.zeros(len(self.clients),dtype=bool)
            peak=np.zeros(len(self.clients));retained=high.copy();confirmed=high.copy()
        baseline=set(basis['quarantine_current_round']);envelope={c for c,yes in zip(self.clients,confirmed,strict=True) if yes}
        selected=baseline|envelope;records=copy.deepcopy(basis['clients']);quarantine=[];reviews=[];rejected=[];transitions={}
        for i,c in enumerate(self.clients):
            previous=c in self._quarantined
            if not mandatory_gate[c]:action='protocol_reject';rejected.append(c)
            elif not basis['supported']:action='abstain_requires_review';reviews.append(c)
            elif c in selected:action='quarantine_current_round';quarantine.append(c)
            elif high[i] or previous or records[c]['action']=='review_required':action='review_required';reviews.append(c)
            else:action='no_statistical_alert'
            transition=('continued' if previous else 'entered') if c in quarantine else ('released' if previous else 'confirmation_pending' if retained[i] else 'none')
            records[c].update(action=action,quarantine_transition=transition,
                baseline_confirmed_proposal=c in baseline,client_envelope_confirmed_proposal=c in envelope,
                client_envelope_current_high=bool(high[i]),client_envelope_current_minimum_excess=float(excess[i]),
                client_envelope_episode_peak_excess=float(peak[i]),client_envelope_non_receding=bool(retained[i]),
                client_envelope_retreat_detected=bool(high[i] and not retained[i]),
                quarantine_evidence_sources=([s for s,yes in [('baseline',c in baseline),('client-envelope',c in envelope)] if yes] if c in quarantine else []))
            transitions[c]=transition
        weights={c:Fraction(str(masses[c])) for c in self.clients}
        effective={c:Fraction(0) if c in quarantine or c in rejected else weights[c] for c in self.clients}
        quorum=sum(v>0 for v in effective.values())>=self.minimum and sum(effective.values(),Fraction(0))>0
        core={'profile':PROFILE,'policy_kind':'baseline-or-client-envelope-retreat','round':round_number,
            'source_observation_sha256':source_observation_sha256,'calibration_digest':basis['calibration_digest'],
            'envelope_calibration_digest':self.envelope_digest,'baseline_decision_digest':basis['decision_digest'],
            'input_digest':digest({'basis':basis['input_digest'],'envelope':self.envelope_digest}),
            'previous_decision_digest':self.head,'supported':basis['supported'],'clients':records,
            'quarantine_current_round':quarantine,'review_required':reviews,'mandatory_rejections':rejected,
            'baseline_quarantine_current_round':sorted(baseline),'envelope_quarantine_current_round':sorted(envelope),
            'quarantine_transitions':transitions,'proposed_effective_masses':{c:str(v) for c,v in effective.items()},
            'proposal_quorum_satisfied':quorum,'minimum_contributors':self.minimum,
            'retained_peak_fraction':.5,'cumulative_evidence_role':'review_only',
            'automatic_deployment_validated':False,'client_ban_performed':False}
        result={**core,'decision_digest':digest(core)}
        self._last_previous=self.head;self._last_basis_digest=basis['decision_digest'];self.head=result['decision_digest'];self.round=round_number
        self._peak=peak;self._previous_retained=retained;self._quarantined=set(quarantine);self.last_result=copy.deepcopy(result)
        return result
