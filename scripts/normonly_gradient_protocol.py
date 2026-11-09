"""Separate uniform root-norm research ablation with explicit pause semantics.

This validates context/content bindings and supplied mandatory-gate results.
It does not obtain TPM Quotes or replace authentication of those supplied facts.
"""
from __future__ import annotations
import hashlib,json
import numpy as np
from normonly_aggregation import normonly_delta as fltrust_delta

PROFILE='coherent-normonly-ablation-round-v1'
QUORUM=10

def digest(v):
    return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def valid_digest(v):return isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v)
def array_record(values):return [{'shape':list(a.shape),'values':a.ravel().tolist()} for a in values]
def arrays(values):
    result=[np.asarray(a,dtype=np.float64) for a in values]
    if not result or any(a.size==0 or not np.isfinite(a).all() for a in result):raise ValueError('invalid tensors')
    return result
def delta_digest(values):return digest(array_record(arrays(values)))

def make_context(*,parent_model_sha256,base_tensor_digest,round_number,attempt_id,protocol_sha256,loss_contract_sha256,roster,method,root_reference_sha256=None):
    if not all(valid_digest(v) for v in (parent_model_sha256,base_tensor_digest,protocol_sha256,loss_contract_sha256)):raise ValueError('invalid context digest')
    if type(round_number) is not int or round_number<1 or not isinstance(attempt_id,str) or not attempt_id:raise ValueError('invalid attempt')
    if not roster or len(set(roster))!=len(roster) or any(not isinstance(c,str) or not c for c in roster):raise ValueError('invalid roster')
    if method not in ('coherent_fedavg','coherent_normonly'):raise ValueError('unknown operator')
    if method=='coherent_normonly' and not valid_digest(root_reference_sha256):raise ValueError('missing root binding')
    core=dict(profile=PROFILE,parent_model_sha256=parent_model_sha256,base_tensor_digest=base_tensor_digest,round_number=round_number,attempt_id=attempt_id,
              protocol_sha256=protocol_sha256,loss_contract_sha256=loss_contract_sha256,roster=sorted(roster),method=method,
              root_reference_sha256=root_reference_sha256,minimum_positive_contributors=QUORUM)
    return {**core,'context_digest':digest(core)}

def check_context(context):
    core={k:v for k,v in context.items() if k!='context_digest'}
    if digest(core)!=context.get('context_digest') or core.get('profile')!=PROFILE or core.get('minimum_positive_contributors')!=QUORUM:
        raise ValueError('changed context or quorum contract')

def update_record(client_id,context,delta,example_count,mandatory_gate=True):
    return {'client_id':client_id,'context_digest':context['context_digest'],'delta':delta,
            'delta_digest':delta_digest(delta),'example_count':example_count,'mandatory_gate':mandatory_gate}

def assess_round(base,updates,root,context):
    check_context(context);base=arrays(base);roster=context['roster'];clients=sorted(updates)
    if digest(array_record(base))!=context['base_tensor_digest']:raise ValueError('base tensors do not match bound parent')
    if not set(clients)<=set(roster):raise ValueError('unexpected client')
    deltas={};counts={};gates={}
    for c in clients:
        u=updates[c]
        if u['client_id']!=c or u['context_digest']!=context['context_digest']:raise ValueError('stale or wrong client update context')
        if type(u['example_count']) is not int or u['example_count']<=0 or type(u['mandatory_gate']) is not bool:raise ValueError('invalid input facts')
        d=arrays(u['delta'])
        if len(d)!=len(base) or any(a.shape!=b.shape for a,b in zip(d,base,strict=True)):raise ValueError('changed tensor schema')
        if delta_digest(d)!=u['delta_digest']:raise ValueError('changed update payload')
        deltas[c]=d;counts[c]=u['example_count'];gates[c]=u['mandatory_gate']
    eligible=[c for c in clients if gates[c]]
    event={'profile':PROFILE,'context':context,'received_clients':clients,'missing_clients':sorted(set(roster)-set(clients)),
        'eligible_count':len(eligible),'input_delta_digests':{c:updates[c]['delta_digest'] for c in clients},
        'mandatory_gates':gates,'example_counts':counts,'positive_contributors':0,
        'decision':'defer','reasons':[],'pre_export_parameters_digest':None,'aggregation':None}
    if len(eligible)<QUORUM:
        event['reasons']=['insufficient_eligible_contributors'];return None,event
    if context['method']=='coherent_fedavg':
        total=sum(counts[c] for c in eligible);coeff={c:counts[c]/total if gates[c] else 0. for c in clients}
        delta=[sum((coeff[c]*deltas[c][k] for c in clients),np.zeros_like(a)) for k,a in enumerate(base)]
        event['positive_contributors']=sum(v>0 for v in coeff.values());event['aggregation']={'coefficients':coeff}
    else:
        if root is None or root.get('context_digest')!=context['context_digest'] or root.get('reference_sha256')!=context['root_reference_sha256']:
            raise ValueError('stale or wrong root reference')
        rd=arrays(root['delta'])
        if delta_digest(rd)!=root['delta_digest']:raise ValueError('changed root payload')
        if len(rd)!=len(base) or any(a.shape!=b.shape for a,b in zip(rd,base,strict=True)):raise ValueError('changed root schema')
        try:delta,details=fltrust_delta(deltas,rd,gates)
        except ValueError as exc:
            event['reasons']=['undefined_reference_or_nonzero_support'];event['undefined_detail']=str(exc);return None,event
        event['aggregation']=details;event['positive_contributors']=details['positive_contributors']
        if event['positive_contributors']<QUORUM:
            event['reasons']=['insufficient_positive_contributors'];return None,event
    parameters=[a+d for a,d in zip(base,delta,strict=True)]
    if not all(np.isfinite(a).all() for a in parameters):raise ValueError('invalid numerical output')
    event['decision']='commit';event['pre_export_parameters_digest']=digest(array_record(parameters))
    return parameters,event

def initial_state(parent_model_sha256,protocol_sha256):
    if not valid_digest(parent_model_sha256) or not valid_digest(protocol_sha256):raise ValueError('invalid initial state')
    return {'phase':'active','last_committed_round':0,'parent_model_sha256':parent_model_sha256,'protocol_sha256':protocol_sha256}

def transition(state,event,exported_model_sha256):
    context=event['context'];check_context(context)
    if state['phase']!='active':raise ValueError('paused state requires an explicit future recovery procedure')
    if context['protocol_sha256']!=state['protocol_sha256'] or context['parent_model_sha256']!=state['parent_model_sha256'] or context['round_number']!=state['last_committed_round']+1:
        raise ValueError('wrong parent, protocol or next round')
    details=event.get('aggregation')
    if details:
        scores=details['coefficients'] if context['method']=='coherent_fedavg' else details['scores']
        if event['positive_contributors']!=sum(v>0 for v in scores.values()):raise ValueError('changed support count')
        if any(v and not event['mandatory_gates'][c] for c,v in scores.items()):raise ValueError('vetoed mass restored')
    if event['decision']=='defer':
        if exported_model_sha256 is not None or event['pre_export_parameters_digest'] is not None:raise ValueError('deferred round cannot publish a new checkpoint')
        return {**state,'phase':'paused','last_attempt_context_digest':context['context_digest'],'reasons':event['reasons'],
                'resume_requires_new_evidence_and_explicit_action':True}
    if event['decision']!='commit' or not valid_digest(exported_model_sha256) or not valid_digest(event['pre_export_parameters_digest']) or event['positive_contributors']<QUORUM or event['eligible_count']<QUORUM or event['reasons']:
        raise ValueError('invalid commit')
    return {**state,'last_committed_round':context['round_number'],'parent_model_sha256':exported_model_sha256,
            'last_attempt_context_digest':context['context_digest']}

def verify_round(base,updates,root,context,event):
    params,expected=assess_round(base,updates,root,context)
    if expected!=event:raise ValueError('round event does not reconstruct')
    return params

def common_loss_gradient(model,features,labels,effective_class_weights,torch):
    """Arithmetic mean of weighted losses: no client-local weight-sum division."""
    model.eval()
    loss=torch.nn.functional.cross_entropy(model(features),labels,weight=effective_class_weights,reduction='none').mean()
    grad=torch.autograd.grad(loss,tuple(model.parameters()))
    return [v.detach().cpu().numpy().copy() for v in grad],float(loss.detach())
