"""Causal, round-scoped decisions over calibrated observable update risks.

Review preserves single-view alerts. Quarantine is a proposal for one round, not
a semantic judgment or permanent client ban. Mandatory gates take precedence.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
from fractions import Fraction

import numpy as np

PROFILE = 'sequential-round-decision-v1'
VIEWS = ('conditioned', 'state-disabled')


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def _sequence(record,clients=None):
    allowed={'sequence_id','cohort_id','clients','risk','supported','frame_ids','source_commitment'}
    if set(record)-allowed:raise ValueError('only observable risk sequences are allowed')
    names=list(record['clients'])
    if names!=sorted(set(names)) or len(names)<3 or (clients is not None and names!=clients):raise ValueError('risk population mismatch')
    if set(record['risk'])!=set(VIEWS):raise ValueError('both calibrated views are required')
    values=np.stack([np.asarray(record['risk'][v],dtype=np.float64) for v in VIEWS],axis=2)
    support=np.asarray(record['supported'],dtype=bool)
    if values.ndim!=3 or values.shape[1:]!=(len(names),2) or support.shape!=(len(values),) or not len(values):raise ValueError('invalid risk sequence shape')
    if not np.isfinite(values).all() or np.any(values<0):raise ValueError('invalid risk values')
    if len(record['frame_ids'])!=len(values) or len(set(record['frame_ids']))!=len(values):raise ValueError('invalid source frame IDs')
    return names,values,support


def calibrate_sequential_policy(normalizer_sequences,threshold_sequences,*,horizon=15,drift=.5,minimum_consecutive=2):
    if not normalizer_sequences or not threshold_sequences or horizon<2 or minimum_consecutive!=2 or drift!=.5:raise ValueError('unsupported sequential calibration profile')
    clients=None;cohort=None;normal=[];normal_ids=set()
    for record in normalizer_sequences:
        names,values,support=_sequence(record,clients)
        clients=names if clients is None else clients
        cohort=record['cohort_id'] if cohort is None else cohort
        if record['cohort_id']!=cohort:raise ValueError('cohort changed')
        if normal_ids&set(record['frame_ids']):raise ValueError('normalizer frames overlap')
        normal_ids.update(record['frame_ids']);normal.append(values[support])
    normal=np.concatenate(normal)
    if not len(normal):raise ValueError('no supported normalizer frames')
    centers=np.median(normal,axis=0);scales=np.maximum(.05,1.4826*np.median(np.abs(normal-centers),axis=0))
    frame_scores=[];cumulative_scores=[];source_ids=set();stress_sequences=0
    for record in threshold_sequences:
        _,values,supported=_sequence(record,clients)
        if record['cohort_id']!=cohort:raise ValueError('cohort changed')
        if normal_ids&set(record['frame_ids']):raise ValueError('normalizer/threshold overlap')
        source_ids.update(record['frame_ids'])
        z=np.maximum(0.,(values-centers)/scales)
        if not np.isfinite(z).all():raise ValueError('nonrepresentable standardized risk')
        # Short historical response banks are cyclic null stress sequences, not
        # new independent campaigns. Every rotation is included, never selected.
        starts=range(len(z)) if len(z)<horizon else (0,)
        if len(z)>horizon:raise ValueError('threshold history exceeds the declared horizon')
        for start in starts:
            accumulator=np.zeros((len(clients),2))
            for number in range(horizon):
                index=(start+number)%len(z)
                if not supported[index]:accumulator[:]=0;continue
                accumulator=np.maximum(0.,accumulator+z[index]-drift)
                frame_scores.append(z[index]);cumulative_scores.append(accumulator.copy())
            stress_sequences+=1
    if not frame_scores:raise ValueError('no supported threshold frames')
    frame_scores=np.stack(frame_scores);cumulative_scores=np.stack(cumulative_scores)
    return {'profile':PROFILE,'cohort_id':cohort,'clients':clients,'horizon':horizon,'drift':drift,
        'minimum_consecutive':minimum_consecutive,'centers':centers.tolist(),'scales':scales.tolist(),
        'instantaneous_limits':(frame_scores.max(axis=(0,1))+1.).tolist(),
        'cumulative_limits':(cumulative_scores.max(axis=(0,1))+1.).tolist(),
        'review_instantaneous_limits':(np.quantile(frame_scores,.99,axis=(0,1))+.25).tolist(),
        'review_cumulative_limits':(np.quantile(cumulative_scores,.99,axis=(0,1))+.25).tolist(),
        'normalizer_frame_ids':sorted(normal_ids),'threshold_unique_frame_ids':sorted(source_ids),
        'threshold_source_sequences':len(threshold_sequences),'including_cyclic_null_stress_sequences':stress_sequences,
        'automatic_deployment_validated':False,
        'qualification':'Empirical maximum over clients, prefixes and declared clean/null sequences. Rotations are dependent stress sequences, not independent false-positive trials.'}


class SequentialRoundPolicy:
    def __init__(self,calibration,*,minimum_contributors=8,kind='sequential'):
        self.cal=copy.deepcopy(calibration)
        if self.cal.get('profile')!=PROFILE or kind not in ('sequential','instantaneous'):raise ValueError('unknown decision profile')
        self.clients=list(self.cal['clients']);self.kind=kind;self.minimum=minimum_contributors
        if self.clients!=sorted(set(self.clients)) or not 1<=minimum_contributors<=len(self.clients):raise ValueError('invalid population/quorum')
        if self.cal['drift']!=.5 or self.cal['minimum_consecutive']!=2 or self.cal['horizon']<2:raise ValueError('changed sequential protocol')
        self.centers=np.asarray(self.cal['centers'],dtype=float);self.scales=np.asarray(self.cal['scales'],dtype=float)
        if self.centers.shape!=(len(self.clients),2) or self.scales.shape!=self.centers.shape or not np.isfinite(self.centers).all() or not np.isfinite(self.scales).all() or np.any(self.scales<.05):raise ValueError('invalid score normalization')
        for key in ('instantaneous_limits','cumulative_limits','review_instantaneous_limits','review_cumulative_limits'):
            values=np.asarray(self.cal[key],dtype=float)
            if values.shape!=(2,) or not np.isfinite(values).all() or np.any(values<=0):raise ValueError('invalid decision thresholds')
        self.calibration_digest=digest(self.cal);self.round=0;self.head='0'*64
        self.cumulative=np.zeros((len(self.clients),2));self.streak=np.zeros((len(self.clients),2),dtype=int)
        self.last_input=None;self.last_previous=None;self.last_result=None

    def step(self,round_number,risk,*,context_supported,mandatory_gate,masses,expected_previous_digest,source_observation_sha256):
        if not isinstance(source_observation_sha256,str) or len(source_observation_sha256)!=64 or any(c not in '0123456789abcdef' for c in source_observation_sha256):raise ValueError('invalid source observation commitment')
        if set(mandatory_gate)!=set(self.clients) or any(type(v) is not bool for v in mandatory_gate.values()):raise ValueError('invalid mandatory gate population')
        if set(masses)!=set(self.clients):raise ValueError('invalid mass population')
        weights={c:Fraction(str(masses[c])) for c in self.clients}
        if any(v<0 for v in weights.values()):raise ValueError('negative mass')
        if type(context_supported) is not bool:raise ValueError('invalid context support')
        effective_support=context_supported and all(mandatory_gate.values())
        if risk is None:
            if effective_support:raise ValueError('missing supported risk')
            values=None
        else:
            if set(risk)!=set(VIEWS):raise ValueError('risk views changed')
            values=np.stack([np.asarray(risk[v],dtype=float) for v in VIEWS],axis=1)
            if values.shape!=(len(self.clients),2) or not np.isfinite(values).all() or np.any(values<0):raise ValueError('invalid frame risks')
        inputs={'round':round_number,'source_observation_sha256':source_observation_sha256,'risk':None if values is None else values.tolist(),
            'context_supported':context_supported,'mandatory_gate':mandatory_gate,
            'masses':{c:str(v) for c,v in weights.items()},'kind':self.kind}
        input_digest=digest(inputs)
        if round_number==self.round:
            if input_digest==self.last_input and expected_previous_digest==self.last_previous:return copy.deepcopy(self.last_result)
            raise ValueError('conflicting retry or predecessor')
        if round_number!=self.round+1 or round_number>self.cal['horizon'] or expected_previous_digest!=self.head:raise ValueError('round order or trusted predecessor mismatch')
        previous=self.head
        if effective_support:
            z=np.maximum(0.,(values-self.centers)/self.scales)
            if not np.isfinite(z).all():raise ValueError('nonrepresentable standardized risk')
            cumulative=np.maximum(0.,self.cumulative+z-self.cal['drift'])
            streak=np.where(z>self.cal['drift'],self.streak+1,0)
            instant_votes=z>np.asarray(self.cal['instantaneous_limits'])
            sequential_votes=(cumulative>np.asarray(self.cal['cumulative_limits']))&(z>self.cal['drift'])&(streak>=2)
            warning=(z>np.asarray(self.cal['review_instantaneous_limits']))|(cumulative>np.asarray(self.cal['review_cumulative_limits']))
        else:
            z=None;cumulative=np.zeros_like(self.cumulative);streak=np.zeros_like(self.streak)
            instant_votes=np.zeros_like(streak,dtype=bool);sequential_votes=instant_votes.copy();warning=instant_votes.copy()
        eligible_mass={c:weights[c] if mandatory_gate[c] else Fraction(0) for c in self.clients}
        total=sum(eligible_mass.values(),Fraction(0));records={};quarantine=[];reviews=[];rejected=[]
        for index,client in enumerate(self.clients):
            pre_weight=eligible_mass[client]/total if total else None
            votes=sequential_votes[index] if self.kind=='sequential' else instant_votes[index]
            disagreement=bool((warning[index,0]!=warning[index,1]) or (sequential_votes[index,0]!=sequential_votes[index,1]))
            if not mandatory_gate[client]:action='protocol_reject';rejected.append(client)
            elif not effective_support:action='abstain_requires_review';reviews.append(client)
            elif bool(votes.all()):action='quarantine_current_round';quarantine.append(client)
            elif bool(warning[index].any()) or disagreement:action='review_required';reviews.append(client)
            else:action='no_statistical_alert'
            importance=0. if z is None else float(np.maximum(z[index]/np.asarray(self.cal['review_instantaneous_limits']),cumulative[index]/np.asarray(self.cal['review_cumulative_limits'])).max())
            priority=(float(pre_weight) if pre_weight is not None else 0.)*(importance if effective_support else 1.)
            records[client]={'action':action,'mandatory_gate_passed':mandatory_gate[client],
                'standardized_risk':None if z is None else dict(zip(VIEWS,map(float,z[index]),strict=True)),
                'cumulative_evidence':dict(zip(VIEWS,map(float,cumulative[index]),strict=True)),
                'consecutive_supported_exceedances':dict(zip(VIEWS,map(int,streak[index]),strict=True)),
                'view_disagreement':disagreement,'instantaneous_proposal':bool(instant_votes[index].all()),
                'sequential_proposal':bool(sequential_votes[index].all()),
                'pre_policy_weight':None if pre_weight is None else {'numerator':str(pre_weight.numerator),'denominator':str(pre_weight.denominator)},
                'review_priority':priority,'semantic_malice_proved':False}
        post_mass={c:(Fraction(0) if c in quarantine or c in rejected else weights[c]) for c in self.clients}
        positive=sum(v>0 for v in post_mass.values());quorum=positive>=self.minimum and sum(post_mass.values(),Fraction(0))>0
        core={'profile':PROFILE,'round':round_number,'source_observation_sha256':source_observation_sha256,'policy_kind':self.kind,'calibration_digest':self.calibration_digest,
            'input_digest':input_digest,'previous_decision_digest':previous,'supported':effective_support,
            'clients':records,'quarantine_current_round':quarantine,'review_required':reviews,'mandatory_rejections':rejected,
            'proposed_effective_masses':{c:str(v) for c,v in post_mass.items()},'proposal_quorum_satisfied':quorum,
            'minimum_contributors':self.minimum,'automatic_deployment_validated':False,'client_ban_performed':False}
        result={**core,'decision_digest':digest(core)}
        self.cumulative=cumulative;self.streak=streak;self.round=round_number;self.head=result['decision_digest']
        self.last_input=input_digest;self.last_previous=previous;self.last_result=copy.deepcopy(result)
        return result
