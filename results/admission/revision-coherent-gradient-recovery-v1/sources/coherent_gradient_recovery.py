"""One explicit research recovery after strict growth of authenticated root data."""
from coherent_gradient_protocol import digest,valid_digest,check_context

def resume_after_root_expansion(state,paused_context,old_root_manifest,new_root_manifest,new_protocol_sha256):
    check_context(paused_context)
    if state.get('root_expansion_count',0)>=1:raise ValueError('single root-expansion budget exhausted')
    if state['phase']!='paused' or state['last_attempt_context_digest']!=paused_context['context_digest']:
        raise ValueError('state is not the anchored paused attempt')
    if state['parent_model_sha256']!=paused_context['parent_model_sha256'] or state['last_committed_round']+1!=paused_context['round_number']:
        raise ValueError('paused parent or round changed')
    if digest(old_root_manifest)!=paused_context['root_reference_sha256']:raise ValueError('old reference not anchored')
    if not valid_digest(new_protocol_sha256) or new_protocol_sha256==state['protocol_sha256']:raise ValueError('explicit new recovery policy required')
    for key in ('source_validation_sha256','loss_contract'):
        if old_root_manifest[key]!=new_root_manifest[key]:raise ValueError('source or loss contract changed')
    if old_root_manifest['loss_contract']!=paused_context['loss_contract_sha256']:raise ValueError('wrong loss contract')
    old_ids=old_root_manifest['window_ids'];new_ids=new_root_manifest['window_ids']
    if len(set(old_ids))!=len(old_ids) or len(set(new_ids))!=len(new_ids) or not set(old_ids)<set(new_ids):
        raise ValueError('recovery requires additional root evidence, not an identical retry')
    proof={'old_context_digest':paused_context['context_digest'],'old_protocol_sha256':state['protocol_sha256'],
        'old_root_sha256':digest(old_root_manifest),'new_root_sha256':digest(new_root_manifest),
        'additional_root_ids':sorted(set(new_ids)-set(old_ids)),
        'retained_parent_model_sha256':state['parent_model_sha256'],'retained_committed_round':state['last_committed_round'],
        'paused_reasons':state.get('reasons',[])}
    new_state={**state,'phase':'active','protocol_sha256':new_protocol_sha256,'root_expansion_proof_sha256':digest(proof),
        'recovered_from_context_digest':paused_context['context_digest'],'root_expansion_count':1,'reasons':[],
        'resume_requires_new_evidence_and_explicit_action':False,'root_reference_sha256':digest(new_root_manifest)}
    return new_state,proof
